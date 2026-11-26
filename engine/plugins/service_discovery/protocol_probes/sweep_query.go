// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/postgres"
)

// missListSQL is the batch equivalent of the serial walk's filters:
// ListDone ∩ open_port (prefilter TTL) ∩ ¬Protocol-Probes (plugin TTL) ∩
// resolved by an FQDN under a seed domain. Does not use fqdn_by_domains —
// that function is not in stock asset-db.
//
// It starts from the Done IPs, as the serial walk does, so every lookup is
// an index probe keyed by one IP: its tags (entity_id, ...), its incoming
// dns_record edges (to_entity_id), and the FQDN behind each edge. The cost
// grows with the number of Done IPs, not with the size of the database.
// (Starting from the seed domains instead needs a pattern match per seed,
// which the planner cannot run as an index range inside a join; it read the
// whole entity and fqdn tables and hit statement_timeout on large
// databases.) OFFSET 0 keeps each subquery a per-row probe: without it the
// planner can turn EXISTS into a hash semi-join over a full table scan.
const missListSQL = `
WITH seeds AS MATERIALIZED (
    SELECT DISTINCT reverse(lower(trim(s))) AS rd
    FROM unnest(string_to_array($2::text, E'\n')) AS s
    WHERE trim(s) <> ''
)
SELECT d.id::text
FROM unnest($1::bigint[]) AS d(id)
WHERE EXISTS (
    SELECT 1 FROM entity_tag t
    WHERE t.entity_id = d.id
      AND t.property_name = 'open_port'
      AND t.updated_at >= $3
    OFFSET 0
)
AND NOT EXISTS (
    SELECT 1 FROM entity_tag t
    WHERE t.entity_id = d.id
      AND t.property_name = 'last_monitored'
      AND t.property_value = 'Protocol-Probes'
      AND t.updated_at >= $4
    OFFSET 0
)
AND EXISTS (
    SELECT 1
    FROM edge ed
    JOIN entity e ON e.entity_id = ed.from_entity_id
    JOIN fqdn f ON f.id = e.row_id
    WHERE ed.to_entity_id = d.id
      AND ed.label = 'dns_record'
      AND e.etype_id = (SELECT id FROM entity_type_lu WHERE name = 'fqdn')
      AND EXISTS (
          SELECT 1 FROM seeds sd
          WHERE f.reverse_fqdn = sd.rd
             OR starts_with(f.reverse_fqdn, sd.rd || '.')
      )
    OFFSET 0
)
LIMIT $5
`

// missListChunk is how many Done IPs go into one miss-list statement. Each
// statement must finish inside missListStatementTimeout even with a cold
// cache (about 1ms per IP in the worst case measured on a test database).
var missListChunk = 5000

// missListStatementTimeout is the PostgreSQL statement_timeout for one
// miss-list chunk. asset-db opens its *sql.DB with a 60s statement_timeout,
// which a 5,000-IP chunk exceeded on a production-size database. The query
// raises it for its own statement only, with SET LOCAL inside a read-only
// transaction, so the connection's default is unchanged for anything else
// (and SET LOCAL is safe behind a transaction-pooling pgBouncer).
const missListStatementTimeout = 90 * time.Second

// missListQueryTimeout bounds a chunk on the Go side. It equals the statement
// timeout, so a chunk that runs too long may end as either a PostgreSQL
// "canceling statement due to statement timeout" or a Go "context deadline
// exceeded"; both fail the chunk the same way.
const missListQueryTimeout = 90 * time.Second

// maxConsecutiveChunkFailures is how many miss-list chunks in a row may fail
// before the batch gives up and leaves the remaining Done IPs to the serial
// walk. Each failure can take up to missListQueryTimeout, so a query that
// cannot work at all (a schema or permission problem) should not be retried
// on every chunk.
const maxConsecutiveChunkFailures = 3

// runMissListQuery runs one miss-list chunk. Tests replace it.
var runMissListQuery = missListQuery

// repositoryUnwrapper is implemented by repository wrappers that hold the
// asset-db repository underneath, such as the session's write guard.
type repositoryUnwrapper interface {
	Unwrap() repository.Repository
}

// postgresSQL returns the *sql.DB of the session's PostgreSQL repository, or
// nil when the session does not use PostgreSQL. Session.DB() is wrapped (the
// session's write guard), so it unwraps until it reaches the asset-db
// repository; asserting the type on Session.DB() alone never matches.
func postgresSQL(s et.Session) *sql.DB {
	if s == nil {
		return nil
	}
	repo := s.DB()
	for i := 0; i < 8 && repo != nil; i++ {
		if p, ok := repo.(*postgres.PostgresRepository); ok {
			if p == nil {
				return nil
			}
			return p.DB
		}
		u, ok := repo.(repositoryUnwrapper)
		if !ok {
			return nil
		}
		repo = u.Unwrap()
	}
	return nil
}

// missListResult is the outcome of the batched miss-list query.
type missListResult struct {
	// misses are the Done IPs that need a Protocol-Probes requeue. The query
	// has already applied the walk's filters to them.
	misses []string
	// walk are Done IPs from chunks whose query failed. The caller checks
	// them one at a time, with the walk's filters.
	walk []string
	// failedChunks counts the chunks whose query failed.
	failedChunks int
	// slowest is the longest any chunk's query took, failed or not, for
	// tuning missListStatementTimeout and missListChunk.
	slowest time.Duration
}

// missListBatch finds the Done IPs that need a Protocol-Probes requeue with
// one query per missListChunk IPs. ok=false means the batch could not run at
// all and the caller must check every Done IP one at a time; reason says why.
// A chunk whose query fails sends only its own IPs to the walk; after
// maxConsecutiveChunkFailures failures in a row, the remaining IPs go to the
// walk too.
func missListBatch(s et.Session, log *slog.Logger, doneIDs []string, prefilterSince, protoSince time.Time) (res missListResult, ok bool, reason string) {
	db := postgresSQL(s)
	if db == nil {
		return res, false, "the session database is not PostgreSQL"
	}
	if len(doneIDs) == 0 {
		return res, true, ""
	}
	seeds := sweepSeedDomains(s)
	if len(seeds) == 0 {
		return res, true, ""
	}

	ints := make([]int64, 0, len(doneIDs))
	seen := make(map[int64]struct{}, len(doneIDs))
	for _, id := range doneIDs {
		n, perr := strconv.ParseInt(id, 10, 64)
		if perr != nil {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		ints = append(ints, n)
	}
	if len(ints) == 0 {
		return res, true, ""
	}

	chunks := (len(ints) + missListChunk - 1) / missListChunk
	seedList := strings.Join(seeds, "\n")
	consecutive := 0
	for start := 0; start < len(ints) && len(res.misses) < sweepMaxResubmit; start += missListChunk {
		if s.Done() {
			break
		}
		end := min(start+missListChunk, len(ints))
		began := time.Now()
		found, qerr := runMissListQuery(s.Ctx(), db, ints[start:end], seedList,
			prefilterSince, protoSince, sweepMaxResubmit-len(res.misses))
		took := time.Since(began)
		res.slowest = max(res.slowest, took)
		if qerr == nil {
			consecutive = 0
			res.misses = append(res.misses, found...)
			continue
		}

		res.failedChunks++
		consecutive++
		res.walk = appendIDStrings(res.walk, ints[start:end])
		if log != nil {
			log.Warn("miss-list query failed for a chunk; its IPs will be checked one at a time",
				"chunk", start/missListChunk+1, "chunks", chunks, "ips", end-start,
				"after", took.Round(100*time.Millisecond).String(), "error", qerr.Error())
		}
		if consecutive >= maxConsecutiveChunkFailures {
			res.walk = appendIDStrings(res.walk, ints[end:])
			if log != nil {
				log.Warn("miss-list query failed on consecutive chunks; checking the remaining Done IPs one at a time",
					"failed_in_a_row", consecutive, "remaining_ips", len(ints)-end)
			}
			break
		}
	}
	return res, true, ""
}

func appendIDStrings(dst []string, ids []int64) []string {
	for _, id := range ids {
		dst = append(dst, strconv.FormatInt(id, 10))
	}
	return dst
}

// missListQuery runs missListSQL over one chunk of Done IPs, under
// missListStatementTimeout.
func missListQuery(ctx context.Context, db *sql.DB, ids []int64, seeds string, prefilterSince, protoSince time.Time, limit int) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, missListQueryTimeout)
	defer cancel()

	var out []string
	err := withStatementTimeout(ctx, db, missListStatementTimeout, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, missListSQL,
			pgInt8Array(ids),
			seeds,
			prefilterSince.UTC(),
			protoSince.UTC(),
			limit,
		)
		if err != nil {
			return fmt.Errorf("miss-list query: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// withStatementTimeout runs fn in a read-only transaction whose
// statement_timeout is timeout. SET LOCAL ends with the transaction, so the
// connection keeps asset-db's own setting afterwards.
func withStatementTimeout(ctx context.Context, db *sql.DB, timeout time.Duration, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("miss-list query: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
		return fmt.Errorf("miss-list query: set statement_timeout: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func pgInt8Array(ids []int64) string {
	var b strings.Builder
	b.Grow(2 + len(ids)*12)
	b.WriteByte('{')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatInt(id, 10))
	}
	b.WriteByte('}')
	return b.String()
}
