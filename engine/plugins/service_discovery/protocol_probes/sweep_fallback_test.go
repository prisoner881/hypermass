// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// wrappedRepo stands in for the session's write guard
// (engine/sessions/write_guard.go): it embeds a repository and unwraps to
// another. Session.DB() returns such a wrapper, never the asset-db type.
type wrappedRepo struct {
	repository.Repository
	inner repository.Repository
}

func (w *wrappedRepo) Unwrap() repository.Repository { return w.inner }

func wrap(r repository.Repository) *wrappedRepo { return &wrappedRepo{Repository: r, inner: r} }

// lazyPostgres returns a PostgresRepository whose *sql.DB never connects
// (sql.Open does not dial), for tests that stub the query itself.
func lazyPostgres(t *testing.T) (*postgres.PostgresRepository, *sql.DB) {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &postgres.PostgresRepository{DB: db}, db
}

// The session wraps its repository in the write guard; postgresSQL must see
// through it. Before the fix this returned nil for every wrapped repository,
// so every session-end sweep walked all Done IPs one at a time.
func TestPostgresSQLUnwrapsSessionGuard(t *testing.T) {
	pg, sqlDB := lazyPostgres(t)
	lite := newSweepTestSession(t).db

	cases := []struct {
		name string
		db   repository.Repository
		want *sql.DB
	}{
		{"postgres", pg, sqlDB},
		{"guarded postgres", wrap(pg), sqlDB},
		{"twice-wrapped postgres", wrap(wrap(pg)), sqlDB},
		{"sqlite", lite, nil},
		{"guarded sqlite", wrap(lite), nil},
		{"no database", nil, nil},
	}
	for _, c := range cases {
		s := &sweepTestSession{db: c.db, cfg: config.NewConfig()}
		if got := postgresSQL(s); got != c.want {
			t.Errorf("%s: postgresSQL returned %p, want %p", c.name, got, c.want)
		}
	}
}

// stubQueries replaces the miss-list query. fail lists the 1-based chunk
// numbers that return an error; other chunks return their IDs that are in
// miss. It returns the chunk numbers queried.
func stubQueries(t *testing.T, chunkSize int, fail []int, miss map[int64]bool) *[]int {
	t.Helper()
	oldChunk, oldRun := missListChunk, runMissListQuery
	t.Cleanup(func() { missListChunk, runMissListQuery = oldChunk, oldRun })
	missListChunk = chunkSize

	var mu sync.Mutex
	var called []int
	runMissListQuery = func(_ context.Context, _ *sql.DB, ids []int64, _ string, _, _ time.Time, limit int) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		n := len(called) + 1
		called = append(called, n)
		if slices.Contains(fail, n) {
			return nil, errors.New("simulated statement timeout")
		}
		var out []string
		for _, id := range ids {
			if miss[id] && len(out) < limit {
				out = append(out, strconv.FormatInt(id, 10))
			}
		}
		return out, nil
	}
	return &called
}

func idStrings(from, to int) []string {
	var out []string
	for i := from; i <= to; i++ {
		out = append(out, strconv.Itoa(i))
	}
	return out
}

func newBatchSession(t *testing.T) *sweepTestSession {
	t.Helper()
	pg, _ := lazyPostgres(t)
	cfg := config.NewConfig()
	cfg.AddDomains("example.com")
	return &sweepTestSession{db: wrap(pg), cfg: cfg}
}

// A chunk whose query fails sends only its own IPs to the walk; the other
// chunks' answers are kept.
func TestMissListBatchChunkFailureWalksOnlyThatChunk(t *testing.T) {
	called := stubQueries(t, 3, []int{2}, map[int64]bool{2: true, 8: true})
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	res, ok, reason := missListBatch(newBatchSession(t), log, idStrings(1, 9), time.Time{}, time.Time{})
	if !ok {
		t.Fatalf("batch not used: %s", reason)
	}
	if !slices.Equal(res.misses, []string{"2", "8"}) {
		t.Errorf("misses = %v, want [2 8]", res.misses)
	}
	if !slices.Equal(res.walk, []string{"4", "5", "6"}) {
		t.Errorf("walk = %v, want the failed chunk [4 5 6]", res.walk)
	}
	if res.failedChunks != 1 || len(*called) != 3 {
		t.Errorf("failedChunks = %d, queries = %d; want 1 and 3", res.failedChunks, len(*called))
	}
	if !strings.Contains(logs.String(), "miss-list query failed for a chunk") ||
		!strings.Contains(logs.String(), "chunk=2 chunks=3 ips=3") {
		t.Errorf("chunk failure not logged as expected:\n%s", logs.String())
	}
}

// After maxConsecutiveChunkFailures failures in a row, the batch stops
// querying and leaves every remaining IP to the walk.
func TestMissListBatchGivesUpAfterConsecutiveFailures(t *testing.T) {
	called := stubQueries(t, 2, []int{2, 3, 4}, map[int64]bool{1: true})
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	res, ok, _ := missListBatch(newBatchSession(t), log, idStrings(1, 12), time.Time{}, time.Time{})
	if !ok {
		t.Fatal("batch not used")
	}
	if len(*called) != 1+maxConsecutiveChunkFailures {
		t.Errorf("queried %d chunks, want %d", len(*called), 1+maxConsecutiveChunkFailures)
	}
	if !slices.Equal(res.misses, []string{"1"}) {
		t.Errorf("misses = %v, want [1]", res.misses)
	}
	if !slices.Equal(res.walk, idStrings(3, 12)) {
		t.Errorf("walk = %v, want IPs 3-12", res.walk)
	}
	if !strings.Contains(logs.String(), "checking the remaining Done IPs one at a time") {
		t.Errorf("give-up not logged:\n%s", logs.String())
	}
}

// A failure that is not consecutive resets the count.
func TestMissListBatchNonConsecutiveFailuresKeepQuerying(t *testing.T) {
	called := stubQueries(t, 1, []int{1, 2, 4, 5, 7, 8}, nil)
	res, ok, _ := missListBatch(newBatchSession(t), nil, idStrings(1, 9), time.Time{}, time.Time{})
	if !ok || len(*called) != 9 || res.failedChunks != 6 || len(res.walk) != 6 {
		t.Errorf("ok=%v queries=%d failed=%d walk=%v; want every chunk queried, 6 failed",
			ok, len(*called), res.failedChunks, res.walk)
	}
}

func TestMissListBatchNotPostgresGivesReason(t *testing.T) {
	s := newSweepTestSession(t)
	s.db = wrap(s.db)
	if _, ok, reason := missListBatch(s, nil, idStrings(1, 3), time.Time{}, time.Time{}); ok ||
		reason != "the session database is not PostgreSQL" {
		t.Errorf("ok=%v reason=%q; want the not-PostgreSQL reason", ok, reason)
	}
}

// ---------------------------------------------------------------------------
// The whole sweep, with a fake backlog and dispatcher.
// ---------------------------------------------------------------------------

type sweepFakeBacklog struct {
	et.Backlog
	done []string
}

func (b *sweepFakeBacklog) ListDone(oam.AssetType) ([]string, error) { return b.done, nil }
func (b *sweepFakeBacklog) Counts(oam.AssetType) (int64, int64, int64, error) {
	return 0, 0, int64(len(b.done)), nil
}
func (b *sweepFakeBacklog) Has(*dbt.Entity) bool { return false }

type sweepFakeDispatcher struct {
	et.Dispatcher
	mu   sync.Mutex
	sent []string
}

func (d *sweepFakeDispatcher) DispatchEvent(e *et.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, e.Entity.Asset.Key())
	return nil
}

type fullSweepSession struct {
	*sweepTestSession
	id      uuid.UUID
	log     *slog.Logger
	backlog *sweepFakeBacklog
}

func (s *fullSweepSession) ID() uuid.UUID       { return s.id }
func (s *fullSweepSession) Log() *slog.Logger   { return s.log }
func (s *fullSweepSession) Backlog() et.Backlog { return s.backlog }

// newFullSweepSession is an active session over db with example.com in
// scope and the transformations the sweep's TTL windows need.
func newFullSweepSession(t *testing.T, db repository.Repository, logs *bytes.Buffer) *fullSweepSession {
	t.Helper()
	cfg := config.NewConfig()
	cfg.Active = true
	cfg.AddDomains("example.com")
	for _, from := range []string{"ipaddress", "fqdn"} {
		cfg.Transformations[from+"->all"] = &config.Transformation{From: from, To: "all", TTL: 1440, Confidence: 50}
	}
	base := &sweepTestSession{db: db, cfg: cfg}
	base.scope = scope.CreateFromConfigScope(base)
	return &fullSweepSession{
		sweepTestSession: base,
		id:               uuid.New(),
		log:              slog.New(slog.NewTextHandler(logs, nil)),
		backlog:          &sweepFakeBacklog{},
	}
}

// sweepIP stores name -dns_record-> addr; with ports, a fresh open_port tag
// per port; with probed, a fresh Protocol-Probes last_monitored mark.
func sweepIP(t *testing.T, db repository.Repository, name, addr string, ports []int, probed bool) *dbt.Entity {
	t.Helper()
	ctx := context.Background()
	fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
	if err != nil {
		t.Fatalf("create FQDN %s: %v", name, err)
	}
	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"})
	if err != nil {
		t.Fatalf("create IP %s: %v", addr, err)
	}
	if _, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}},
		FromEntity: fqdn,
		ToEntity:   ip,
	}); err != nil {
		t.Fatalf("link %s to %s: %v", name, addr, err)
	}
	for _, p := range ports {
		if _, err := db.CreateEntityProperty(ctx, ip, &oamgen.SimpleProperty{
			PropertyName: "open_port", PropertyValue: strconv.Itoa(p),
		}); err != nil {
			t.Fatalf("open_port on %s: %v", addr, err)
		}
	}
	if probed {
		if _, err := db.CreateEntityProperty(ctx, ip, &oamgen.SimpleProperty{
			PropertyName: "last_monitored", PropertyValue: "Protocol-Probes",
		}); err != nil {
			t.Fatalf("last_monitored on %s: %v", addr, err)
		}
	}
	return ip
}

func sqliteRepo(t *testing.T) repository.Repository {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("open SQLite asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Without PostgreSQL the sweep walks every Done IP, and now says why.
func TestSweepWalksAndLogsWhyWhenNotPostgres(t *testing.T) {
	db := sqliteRepo(t)
	var logs bytes.Buffer
	s := newFullSweepSession(t, wrap(db), &logs)
	missed := sweepIP(t, db, "www.example.com", "192.0.2.10", []int{22}, false)
	probed := sweepIP(t, db, "mail.example.com", "192.0.2.11", []int{25}, true)
	outside := sweepIP(t, db, "www.other.net", "192.0.2.12", []int{80}, false)
	s.backlog.done = []string{missed.ID, probed.ID, outside.ID}

	d := &sweepFakeDispatcher{}
	SweepMissedIPs(s, d)

	if !slices.Equal(d.sent, []string{"192.0.2.10"}) {
		t.Errorf("requeued %v, want only 192.0.2.10", d.sent)
	}
	out := logs.String()
	if !strings.Contains(out, "batched miss-list query not available; checking every Done IP one at a time") ||
		!strings.Contains(out, `reason="the session database is not PostgreSQL"`) ||
		!strings.Contains(out, "done_ips=3") {
		t.Errorf("walk reason not logged:\n%s", out)
	}
	if p := support.SnapshotEndWork(s.ID()); p.Candidates != 3 || p.Requeued != 1 || p.Phase != "done" {
		t.Errorf("progress = %+v; want candidates 3, requeued 1, phase done", p)
	}
}

// splitRepo answers entity lookups from SQLite but unwraps to a PostgreSQL
// repository, so the sweep takes the batched path with a stubbed query and
// still finds the entities it requeues.
type splitRepo struct {
	repository.Repository
	pg repository.Repository
}

func (r *splitRepo) Unwrap() repository.Repository { return r.pg }

// Batched misses are requeued without re-checking; a failed chunk's IPs are
// checked one at a time with the walk's filters.
func TestSweepRequeuesBatchMissesThenWalksFailedChunk(t *testing.T) {
	db := sqliteRepo(t)
	pg, _ := lazyPostgres(t)
	var logs bytes.Buffer
	s := newFullSweepSession(t, &splitRepo{Repository: db, pg: pg}, &logs)

	a := sweepIP(t, db, "a.example.com", "192.0.2.20", []int{22}, false) // chunk 1: batch miss
	b := sweepIP(t, db, "b.example.com", "192.0.2.21", []int{22}, true)  // chunk 1: not a miss
	c := sweepIP(t, db, "c.example.com", "192.0.2.22", []int{22}, false) // chunk 2 (fails): walk finds it
	e := sweepIP(t, db, "e.other.net", "192.0.2.23", []int{22}, false)   // chunk 2 (fails): walk rejects it
	s.backlog.done = []string{a.ID, b.ID, c.ID, e.ID}

	aid, _ := strconv.ParseInt(a.ID, 10, 64)
	stubQueries(t, 2, []int{2}, map[int64]bool{aid: true})

	d := &sweepFakeDispatcher{}
	SweepMissedIPs(s, d)

	if !slices.Equal(d.sent, []string{"192.0.2.20", "192.0.2.22"}) {
		t.Errorf("requeued %v, want [192.0.2.20 192.0.2.22]", d.sent)
	}
	out := logs.String()
	if !strings.Contains(out, "batch miss-list query") || !strings.Contains(out, "plugin.failed_chunks=1 plugin.walk_ips=2") {
		t.Errorf("batch summary not logged:\n%s", out)
	}
	if strings.Contains(out, "not available") {
		t.Errorf("batch reported unavailable:\n%s", out)
	}
	if p := support.SnapshotEndWork(s.ID()); p.Candidates != 3 || p.Requeued != 2 {
		t.Errorf("progress = %+v; want candidates 3 (1 miss + 2 to walk), requeued 2", p)
	}
}

// ---------------------------------------------------------------------------
// Against a real PostgreSQL asset database. Set HYPERMASS_TEST_POSTGRES_DSN
// to a URL with no query string (postgres://user:pass@host:5432/dbname) of a
// database the test may fill; asset-db creates its schema there.
// ---------------------------------------------------------------------------

func TestSweepBatchedAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("HYPERMASS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("HYPERMASS_TEST_POSTGRES_DSN not set")
	}
	db, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var logs bytes.Buffer
	s := newFullSweepSession(t, wrap(db), &logs)
	missed := sweepIP(t, db, "www.example.com", "198.51.100.10", []int{22, 443}, false)
	probed := sweepIP(t, db, "mail.example.com", "198.51.100.11", []int{25}, true)
	outside := sweepIP(t, db, "www.other.net", "198.51.100.12", []int{80}, false)
	noPorts := sweepIP(t, db, "ns.example.com", "198.51.100.13", nil, false)
	s.backlog.done = []string{missed.ID, probed.ID, outside.ID, noPorts.ID}

	if got := postgresSQL(s); got == nil {
		t.Fatal("postgresSQL returned nil for a guarded PostgreSQL repository")
	}

	d := &sweepFakeDispatcher{}
	SweepMissedIPs(s, d)

	if !slices.Equal(d.sent, []string{"198.51.100.10"}) {
		t.Errorf("requeued %v, want only 198.51.100.10", d.sent)
	}
	out := logs.String()
	if !strings.Contains(out, "batch miss-list query") ||
		!strings.Contains(out, "plugin.done_ips=4 plugin.misses=1 plugin.failed_chunks=0 plugin.walk_ips=0") {
		t.Errorf("batched path not used:\n%s", out)
	}
}

// The batch summary reports the slowest chunk, for tuning the chunk size
// and statement timeout.
func TestMissListBatchRecordsSlowestChunk(t *testing.T) {
	stubQueries(t, 2, nil, nil)
	inner := runMissListQuery
	runMissListQuery = func(ctx context.Context, db *sql.DB, ids []int64, seeds string, a, b time.Time, limit int) ([]string, error) {
		if ids[0] == 3 {
			time.Sleep(30 * time.Millisecond)
		}
		return inner(ctx, db, ids, seeds, a, b, limit)
	}
	res, ok, _ := missListBatch(newBatchSession(t), nil, idStrings(1, 6), time.Time{}, time.Time{})
	if !ok || res.slowest < 30*time.Millisecond {
		t.Errorf("ok=%v slowest=%v; want the 30ms chunk recorded", ok, res.slowest)
	}
}

// The miss-list query raises statement_timeout for its own transaction only:
// inside it the limit is missListStatementTimeout, and the connection keeps
// asset-db's 60s afterwards. Needs HYPERMASS_TEST_POSTGRES_DSN.
func TestMissListStatementTimeoutIsLocalToTheQuery(t *testing.T) {
	dsn := os.Getenv("HYPERMASS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("HYPERMASS_TEST_POSTGRES_DSN not set")
	}
	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL asset database: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	db := postgresSQL(&sweepTestSession{db: wrap(repo), cfg: config.NewConfig()})
	if db == nil {
		t.Fatal("no *sql.DB behind the guarded repository")
	}
	ctx := context.Background()

	var before, inside, after string
	if err := db.QueryRowContext(ctx, "SHOW statement_timeout").Scan(&before); err != nil {
		t.Fatalf("SHOW before: %v", err)
	}
	// The write below must fail (read-only), which aborts the transaction, so
	// withStatementTimeout's own result is not checked; the SHOW runs first.
	_ = withStatementTimeout(ctx, db, missListStatementTimeout, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SHOW statement_timeout").Scan(&inside); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "CREATE TEMP TABLE should_not_exist (i int)"); err == nil {
			t.Error("the transaction is not read-only")
		}
		return nil
	})
	if err := db.QueryRowContext(ctx, "SHOW statement_timeout").Scan(&after); err != nil {
		t.Fatalf("SHOW after: %v", err)
	}
	if before != "1min" || inside != "90s" || after != "1min" {
		t.Errorf("statement_timeout before=%q inside=%q after=%q; want 1min, 90s, 1min", before, inside, after)
	}
}
