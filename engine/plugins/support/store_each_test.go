// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// recordingDB records the time left before each CreateAsset call's
// deadline, and fails or returns nothing for chosen names.
type recordingDB struct {
	repository.Repository
	left    []time.Duration
	fail    map[string]bool
	nothing map[string]bool
	cancel  func() // called after the first asset, when set
}

func (r *recordingDB) CreateAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error) {
	if d, ok := ctx.Deadline(); ok {
		r.left = append(r.left, time.Until(d))
	}
	if r.cancel != nil {
		defer r.cancel()
	}
	if f, ok := a.(*oamdns.FQDN); ok {
		if r.fail[f.Name] {
			return nil, errors.New("simulated database failure")
		}
		if r.nothing[f.Name] {
			return nil, nil
		}
	}
	return r.Repository.CreateAsset(ctx, a)
}

type cancelSession struct {
	*p1Session
	ctx context.Context
}

func (s *cancelSession) Ctx() context.Context { return s.ctx }

var testSource = &et.Source{Name: "Test", Confidence: 100}

// Every name gets its own deadline. A single deadline for the whole batch
// let a large answer be stored for 30 seconds and failed every name after.
func TestStoreFQDNsEachNameHasItsOwnDeadline(t *testing.T) {
	sess, _ := newP1Session(t, "enforce")
	db := &recordingDB{Repository: sess.db}
	sess.db = db

	var names []string
	for i := 0; i < 50; i++ {
		names = append(names, fmt.Sprintf("host%d.target.com", i))
	}
	results, failed := StoreFQDNsWithSourceCount(sess, names, testSource, "Test", "Test-Handler")
	if failed != 0 || len(results) != len(names) {
		t.Fatalf("stored %d, failed %d; want %d stored", len(results), failed, len(names))
	}
	if len(db.left) != len(names) {
		t.Fatalf("saw %d deadlines, want %d", len(db.left), len(names))
	}
	for i, left := range db.left {
		if left < storeItemTimeout-2*time.Second {
			t.Errorf("name %d: %v left before the deadline, want about %v", i, left, storeItemTimeout)
		}
	}
}

// Failures are counted and logged once, as a summary; the other names are
// stored. A database that returns no entity and no error does not crash it.
func TestStoreFQDNsFailuresSummarized(t *testing.T) {
	sess, logs := newP1Session(t, "enforce")
	sess.db = &recordingDB{
		Repository: sess.db,
		fail:       map[string]bool{"b.target.com": true, "c.target.com": true},
		nothing:    map[string]bool{"d.target.com": true},
	}

	results, failed := StoreFQDNsWithSourceCount(sess,
		[]string{"a.target.com", "b.target.com", "c.target.com", "d.target.com", "e.target.com"},
		testSource, "Test", "Test-Handler")
	if len(results) != 2 || failed != 3 {
		t.Errorf("stored %d, failed %d; want 2 stored, 3 failed", len(results), failed)
	}
	out := logs.String()
	if n := strings.Count(out, "failed to store names"); n != 1 {
		t.Errorf("failure summary logged %d times, want 1:\n%s", n, out)
	}
	for _, want := range []string{"failed=3", "stored=2", "simulated database failure", "Test-Handler"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}

	// the wrapper without a count behaves the same
	if got := StoreFQDNsWithSource(sess, []string{"f.target.com", "b.target.com"}, testSource, "Test", "Test-Handler"); len(got) != 1 {
		t.Errorf("StoreFQDNsWithSource stored %d, want 1", len(got))
	}
}

// When the session ends, storing stops and the names not attempted count
// as failed.
func TestStoreFQDNsStopsWhenSessionEnds(t *testing.T) {
	base, _ := newP1Session(t, "enforce")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base.db = &recordingDB{Repository: base.db, cancel: cancel}
	sess := &cancelSession{p1Session: base, ctx: ctx}

	results, failed := StoreFQDNsWithSourceCount(sess,
		[]string{"a.target.com", "b.target.com", "c.target.com"}, testSource, "Test", "Test-Handler")
	if len(results)+failed != 3 || failed < 2 {
		t.Errorf("stored %d, failed %d; want the names after the session ended counted as failed", len(results), failed)
	}
}

func TestStoreEmailsWithSource(t *testing.T) {
	sess, _ := newP1Session(t, "enforce")
	got := StoreEmailsWithSource(sess, []string{"NOC@Target.com", "abuse@target.com"}, testSource, "Test", "Test-Handler")
	if len(got) != 2 {
		t.Fatalf("stored %d email addresses, want 2", len(got))
	}
	if got[0].Asset.Key() != "email:noc@target.com" {
		t.Errorf("first identifier = %q, want email:noc@target.com", got[0].Asset.Key())
	}
}
