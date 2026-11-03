// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

// fakeRepo records the context each call ran under. A write can be held
// until released, to stand in for a write running in asset-db's shared
// batch transaction.
type fakeRepo struct {
	repository.Repository
	mu      sync.Mutex
	ctxs    []context.Context
	calls   int
	hold    chan struct{} // when set, writes wait for it to close
	started chan struct{} // closed when the first write starts, when set
	errAt   []error       // the write context's error when it was released
}

func (f *fakeRepo) record(ctx context.Context) {
	f.mu.Lock()
	f.ctxs = append(f.ctxs, ctx)
	f.calls++
	f.mu.Unlock()
}

func (f *fakeRepo) write(ctx context.Context) error {
	f.record(ctx)
	if f.started != nil {
		close(f.started)
		f.started = nil
	}
	if f.hold != nil {
		<-f.hold
		f.mu.Lock()
		f.errAt = append(f.errAt, ctx.Err())
		f.mu.Unlock()
		// what the driver does with a cancelled statement: the write fails
		if ctx.Err() != nil {
			return errors.New("conn closed")
		}
	}
	return nil
}

func (f *fakeRepo) CreateEntity(ctx context.Context, e *dbt.Entity) (*dbt.Entity, error) {
	return e, f.write(ctx)
}
func (f *fakeRepo) CreateAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error) {
	return &dbt.Entity{ID: "1", Asset: a}, f.write(ctx)
}
func (f *fakeRepo) DeleteEntity(ctx context.Context, _ string) error { return f.write(ctx) }
func (f *fakeRepo) CreateEdge(ctx context.Context, e *dbt.Edge) (*dbt.Edge, error) {
	return e, f.write(ctx)
}
func (f *fakeRepo) DeleteEdge(ctx context.Context, _ string) error { return f.write(ctx) }
func (f *fakeRepo) CreateEntityTag(ctx context.Context, _ *dbt.Entity, t *dbt.EntityTag) (*dbt.EntityTag, error) {
	return t, f.write(ctx)
}
func (f *fakeRepo) CreateEntityProperty(ctx context.Context, _ *dbt.Entity, _ oam.Property) (*dbt.EntityTag, error) {
	return &dbt.EntityTag{}, f.write(ctx)
}
func (f *fakeRepo) DeleteEntityTag(ctx context.Context, _ string) error { return f.write(ctx) }
func (f *fakeRepo) CreateEdgeTag(ctx context.Context, _ *dbt.Edge, t *dbt.EdgeTag) (*dbt.EdgeTag, error) {
	return t, f.write(ctx)
}
func (f *fakeRepo) CreateEdgeProperty(ctx context.Context, _ *dbt.Edge, _ oam.Property) (*dbt.EdgeTag, error) {
	return &dbt.EdgeTag{}, f.write(ctx)
}
func (f *fakeRepo) DeleteEdgeTag(ctx context.Context, _ string) error { return f.write(ctx) }
func (f *fakeRepo) FindEntityById(ctx context.Context, _ string) (*dbt.Entity, error) {
	f.record(ctx)
	return nil, nil
}

// A write that is running when its caller's timeout expires is not
// cancelled: the caller gets its timeout error, and the write completes.
// Without the guard, the cancelled write closed the shared writer
// connection and failed every other write in its batch.
func TestWriteGuardCallerTimeoutDoesNotCancelWrite(t *testing.T) {
	f := &fakeRepo{hold: make(chan struct{}), started: make(chan struct{})}
	started := f.started
	g := guardWrites(f)

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	done := make(chan error, 1)
	go func() {
		_, err := g.CreateAsset(ctx, &oamdns.FQDN{Name: "www.example.com"})
		done <- err
	}()

	<-started
	cancel() // the caller's timeout expires while the write runs
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("caller got %v, want its own context error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the caller waited past its own context")
	}

	close(f.hold) // the write finishes
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.errAt)
		var werr error
		if n > 0 {
			werr = f.errAt[0]
		}
		f.mu.Unlock()
		if n > 0 {
			if werr != nil {
				t.Errorf("the write's context was cancelled with its caller: %v", werr)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the write never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Every write runs under a context detached from the caller, bounded by
// detachedWriteTimeout instead of the caller's deadline.
func TestWriteGuardEveryWriteDetached(t *testing.T) {
	f := &fakeRepo{}
	g := guardWrites(f)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	ent := &dbt.Entity{ID: "1"}
	edge := &dbt.Edge{ID: "2"}
	prop := &general.SimpleProperty{PropertyName: "p", PropertyValue: "v"}
	writes := map[string]func() error{
		"CreateEntity":         func() error { _, err := g.CreateEntity(ctx, ent); return err },
		"CreateAsset":          func() error { _, err := g.CreateAsset(ctx, &oamdns.FQDN{Name: "a.example.com"}); return err },
		"DeleteEntity":         func() error { return g.DeleteEntity(ctx, "1") },
		"CreateEdge":           func() error { _, err := g.CreateEdge(ctx, edge); return err },
		"DeleteEdge":           func() error { return g.DeleteEdge(ctx, "2") },
		"CreateEntityTag":      func() error { _, err := g.CreateEntityTag(ctx, ent, &dbt.EntityTag{}); return err },
		"CreateEntityProperty": func() error { _, err := g.CreateEntityProperty(ctx, ent, prop); return err },
		"DeleteEntityTag":      func() error { return g.DeleteEntityTag(ctx, "3") },
		"CreateEdgeTag":        func() error { _, err := g.CreateEdgeTag(ctx, edge, &dbt.EdgeTag{}); return err },
		"CreateEdgeProperty":   func() error { _, err := g.CreateEdgeProperty(ctx, edge, prop); return err },
		"DeleteEdgeTag":        func() error { return g.DeleteEdgeTag(ctx, "4") },
	}
	for name, write := range writes {
		f.mu.Lock()
		f.ctxs = nil
		f.mu.Unlock()
		if err := write(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		f.mu.Lock()
		got := f.ctxs
		f.mu.Unlock()
		if len(got) != 1 {
			t.Errorf("%s: %d calls reached the repository, want 1", name, len(got))
			continue
		}
		d, ok := got[0].Deadline()
		if !ok || time.Until(d) > detachedWriteTimeout || time.Until(d) < detachedWriteTimeout-time.Minute {
			t.Errorf("%s: write deadline %v away, want about %v (detached from the caller's hour)",
				name, time.Until(d), detachedWriteTimeout)
		}
	}
}

// A write whose caller's context has already ended is not submitted.
func TestWriteGuardExpiredCallerNotSubmitted(t *testing.T) {
	f := &fakeRepo{}
	g := guardWrites(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := g.CreateAsset(ctx, &oamdns.FQDN{Name: "a.example.com"}); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want the caller's context error", err)
	}
	if f.calls != 0 {
		t.Errorf("%d writes submitted, want 0", f.calls)
	}
}

// Reads pass through under the caller's own context.
func TestWriteGuardReadsPassThrough(t *testing.T) {
	f := &fakeRepo{}
	g := guardWrites(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, _ = g.FindEntityById(ctx, "1")
	if len(f.ctxs) != 1 || f.ctxs[0] != ctx {
		t.Error("a read did not run under the caller's context")
	}
	if guardWrites(nil) != nil {
		t.Error("guarding no repository returned a repository")
	}
}
