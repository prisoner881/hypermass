// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/yl2chen/cidranger"
)

type unroutedTestSession struct {
	et.Session
	id     uuid.UUID
	ranger cidranger.Ranger
}

func (s *unroutedTestSession) ID() uuid.UUID               { return s.id }
func (s *unroutedTestSession) Ctx() context.Context        { return context.Background() }
func (s *unroutedTestSession) CIDRanger() cidranger.Ranger { return s.ranger }

// IP-Netblock does not wait for the BGP prefix of an address whose network
// has no route: it waited 30 seconds on each, for a prefix that never came.
func TestIPNetblockSkipsUnroutedAddress(t *testing.T) {
	sess := &unroutedTestSession{id: uuid.New(), ranger: cidranger.NewPCTrieRanger()}
	defer support.ForgetSession(sess)
	support.RecordUnrouted(sess, netip.MustParseAddr("216.235.193.104"))

	d := NewIPNetblock().(*ipNetblock)
	ent := &dbt.Entity{ID: "1", Asset: &oamnet.IPAddress{Address: netip.MustParseAddr("216.235.193.92"), Type: "IPv4"}}

	start := time.Now()
	if err := d.lookup(&et.Event{Entity: ent, Session: sess}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("waited %v for an unrouted address's prefix, want no wait", took)
	}
}
