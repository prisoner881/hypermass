// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// detachedWriteTimeout bounds a write that its caller stopped waiting for.
// It matches the limit asset-db's PostgreSQL writer puts on one batch.
const detachedWriteTimeout = 5 * time.Minute

// writeGuard keeps a caller's context from cancelling a database write once
// it has been submitted.
//
// asset-db's PostgreSQL repository sends every write through one writer
// connection, which runs a batch of queued writes, from every plugin, as one
// transaction with a savepoint per write, and runs each write under its
// caller's context. When a caller's timeout expires while its write runs,
// the driver cancels the statement by closing the connection, and every
// other write in the batch fails ("savepoint: conn closed", "commit: conn
// closed"). Under load, writes wait in the writer's queue and start with
// little time left, so one plugin's short timeout dropped other plugins'
// writes.
//
// The guard runs each write under a context that the caller cannot cancel,
// bounded by detachedWriteTimeout. The caller still waits no longer than its
// own context allows: if that expires first, the caller gets its error, and
// the write completes in the background. Writes are idempotent upserts. A
// write whose caller's context has already ended is not submitted. Reads use
// asset-db's reader connections, outside any shared transaction, and pass
// through unchanged.
type writeGuard struct {
	repository.Repository
}

func guardWrites(r repository.Repository) repository.Repository {
	if r == nil {
		return nil
	}
	return &writeGuard{Repository: r}
}

type writeResult[T any] struct {
	v   T
	err error
}

func detachedWrite[T any](ctx context.Context, write func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	ch := make(chan writeResult[T], 1)
	go func() {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedWriteTimeout)
		defer cancel()
		v, err := write(wctx)
		ch <- writeResult[T]{v: v, err: err}
	}()

	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func detachedDelete(ctx context.Context, del func(context.Context) error) error {
	_, err := detachedWrite(ctx, func(c context.Context) (struct{}, error) {
		return struct{}{}, del(c)
	})
	return err
}

func (g *writeGuard) CreateEntity(ctx context.Context, entity *dbt.Entity) (*dbt.Entity, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.Entity, error) {
		return g.Repository.CreateEntity(c, entity)
	})
}

func (g *writeGuard) CreateAsset(ctx context.Context, asset oam.Asset) (*dbt.Entity, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.Entity, error) {
		return g.Repository.CreateAsset(c, asset)
	})
}

func (g *writeGuard) DeleteEntity(ctx context.Context, id string) error {
	return detachedDelete(ctx, func(c context.Context) error { return g.Repository.DeleteEntity(c, id) })
}

func (g *writeGuard) CreateEdge(ctx context.Context, edge *dbt.Edge) (*dbt.Edge, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.Edge, error) {
		return g.Repository.CreateEdge(c, edge)
	})
}

func (g *writeGuard) DeleteEdge(ctx context.Context, id string) error {
	return detachedDelete(ctx, func(c context.Context) error { return g.Repository.DeleteEdge(c, id) })
}

func (g *writeGuard) CreateEntityTag(ctx context.Context, entity *dbt.Entity, tag *dbt.EntityTag) (*dbt.EntityTag, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.EntityTag, error) {
		return g.Repository.CreateEntityTag(c, entity, tag)
	})
}

func (g *writeGuard) CreateEntityProperty(ctx context.Context, entity *dbt.Entity, property oam.Property) (*dbt.EntityTag, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.EntityTag, error) {
		return g.Repository.CreateEntityProperty(c, entity, property)
	})
}

func (g *writeGuard) DeleteEntityTag(ctx context.Context, id string) error {
	return detachedDelete(ctx, func(c context.Context) error { return g.Repository.DeleteEntityTag(c, id) })
}

func (g *writeGuard) CreateEdgeTag(ctx context.Context, edge *dbt.Edge, tag *dbt.EdgeTag) (*dbt.EdgeTag, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.EdgeTag, error) {
		return g.Repository.CreateEdgeTag(c, edge, tag)
	})
}

func (g *writeGuard) CreateEdgeProperty(ctx context.Context, edge *dbt.Edge, property oam.Property) (*dbt.EdgeTag, error) {
	return detachedWrite(ctx, func(c context.Context) (*dbt.EdgeTag, error) {
		return g.Repository.CreateEdgeProperty(c, edge, property)
	})
}

func (g *writeGuard) DeleteEdgeTag(ctx context.Context, id string) error {
	return detachedDelete(ctx, func(c context.Context) error { return g.Repository.DeleteEdgeTag(c, id) })
}
