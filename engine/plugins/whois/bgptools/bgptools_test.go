// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/yl2chen/cidranger"
)

func TestParseBGPToolsRecord(t *testing.T) {
	r, err := parseBGPToolsRecord("15148 | 216.235.194.10 | 216.235.194.0/24 | US | ARIN | 2001-01-01 | BLACKBAUD-ASN\n")
	if err != nil || r.ASN != 15148 || r.Prefix.String() != "216.235.194.0/24" || r.ASName != "BLACKBAUD-ASN" {
		t.Errorf("routed answer = %+v, %v", r, err)
	}
	for _, unrouted := range []string{
		"0 | 216.235.193.104 | <nil> | US | ARIN | 2001-01-01 | \n",
		"0 | 216.235.193.104 |  | | | | \n",
	} {
		if _, err := parseBGPToolsRecord(unrouted); !errors.Is(err, errNoRoute) {
			t.Errorf("%q: got %v, want errNoRoute", unrouted, err)
		}
	}
	if _, err := parseBGPToolsRecord("15148 | 216.235.194.10"); err == nil || errors.Is(err, errNoRoute) {
		t.Errorf("short answer: got %v, want a failure", err)
	}
}

// fakeWHOIS answers BGP.Tools-style queries: no route for addresses in
// 216.235.193.0/24, a /24 route for any other address.
type fakeWHOIS struct {
	ln      net.Listener
	queries atomic.Int32
}

func newFakeWHOIS(t *testing.T) *fakeWHOIS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on localhost: %v", err)
	}
	f := &fakeWHOIS{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeWHOIS) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	f.queries.Add(1)
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "begin" || line == "" {
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			return
		}
		if netip.MustParsePrefix("216.235.193.0/24").Contains(addr) {
			_, _ = io.WriteString(c, "0 | "+line+" | <nil> | US | ARIN | 2001-01-01 | \n")
		} else {
			p, _ := addr.Prefix(24)
			_, _ = io.WriteString(c, "15148 | "+line+" | "+p.String()+" | US | ARIN | 2001-01-01 | BLACKBAUD-ASN\n")
		}
		return // one query per connection; "end" is not newline-terminated
	}
}

type bgpTestSession struct {
	et.Session
	id     uuid.UUID
	db     repository.Repository
	cfg    *config.Config
	ranger cidranger.Ranger
	log    *slog.Logger
}

func (s *bgpTestSession) ID() uuid.UUID               { return s.id }
func (s *bgpTestSession) Ctx() context.Context        { return context.Background() }
func (s *bgpTestSession) Log() *slog.Logger           { return s.log }
func (s *bgpTestSession) Config() *config.Config      { return s.cfg }
func (s *bgpTestSession) DB() repository.Repository   { return s.db }
func (s *bgpTestSession) CIDRanger() cidranger.Ranger { return s.ranger }

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// An address with no BGP route is an answer, not a failure: it is logged
// once for its /24, and the /24's other addresses are not sent to BGP.Tools.
// Filling an owned block whose parts are not announced sent 896 addresses
// from one unannounced /24 to BGP.Tools, each logged as an ERROR.
func TestUnroutedNetworkLookedUpOnce(t *testing.T) {
	srv := newFakeWHOIS(t)
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all", TTL: 1440},
	}
	logs := &syncBuffer{}
	sess := &bgpTestSession{id: uuid.New(), db: db, cfg: cfg, ranger: cidranger.NewPCTrieRanger(),
		log: slog.New(slog.NewTextHandler(logs, nil))}
	defer support.ForgetSession(sess)

	bt := NewBGPTools().(*bgpTools)
	bt.addr = "127.0.0.1"
	bt.port = srv.ln.Addr().(*net.TCPAddr).Port
	nb := &netblock{name: bt.name + "-IP-Handler", plugin: bt}

	check := func(addr string) {
		t.Helper()
		ent, err := db.CreateAsset(context.Background(), &oamnet.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"})
		if err != nil {
			t.Fatal(err)
		}
		if err := nb.check(&et.Event{Entity: ent, Session: sess}); err != nil {
			t.Fatal(err)
		}
	}

	for _, addr := range []string{"216.235.193.104", "216.235.193.92", "216.235.193.93"} {
		check(addr)
	}
	if n := srv.queries.Load(); n != 1 {
		t.Errorf("sent %d queries for one unrouted /24, want 1", n)
	}
	out := logs.String()
	if n := strings.Count(out, "no BGP route covers the network"); n != 1 {
		t.Errorf("unrouted network logged %d times, want 1:\n%s", n, out)
	}
	if strings.Contains(out, "failed to obtain a response") {
		t.Errorf("a no-route answer was logged as a failure:\n%s", out)
	}
	if !support.KnownUnrouted(sess, netip.MustParseAddr("216.235.193.250")) {
		t.Error("the unrouted /24 was not recorded")
	}
}

// A failed query is still logged as a failure, and does not crash on its
// error text.
func TestWHOISFailureLogged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on localhost: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // answers nothing
		}
	}()

	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all", TTL: 1440},
	}
	logs := &syncBuffer{}
	sess := &bgpTestSession{id: uuid.New(), db: db, cfg: cfg, ranger: cidranger.NewPCTrieRanger(),
		log: slog.New(slog.NewTextHandler(logs, nil))}
	defer support.ForgetSession(sess)

	bt := NewBGPTools().(*bgpTools)
	bt.addr = "127.0.0.1"
	bt.port = ln.Addr().(*net.TCPAddr).Port
	nb := &netblock{name: bt.name + "-IP-Handler", plugin: bt}

	ent, err := db.CreateAsset(context.Background(), &oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100.7"), Type: "IPv4"})
	if err != nil {
		t.Fatal(err)
	}
	if err := nb.check(&et.Event{Entity: ent, Session: sess}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "failed to obtain a response from the WHOIS server") {
		t.Errorf("a failed query was not logged:\n%s", logs.String())
	}
	if support.KnownUnrouted(sess, netip.MustParseAddr("198.51.100.8")) {
		t.Error("a failed query was recorded as an unrouted network")
	}
}
