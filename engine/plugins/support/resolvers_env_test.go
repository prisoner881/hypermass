// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolverListFromEnv(t *testing.T) {
	// Unset: no override requested.
	t.Run("unset", func(t *testing.T) {
		t.Setenv(EnvResolvers, "")
		got, requested := resolverListFromEnv()
		if requested || got != nil {
			t.Fatalf("unset: got (%v, %v), want (nil, false)", got, requested)
		}
	})

	// Comma-separated list: trims spaces, skips invalid entries, deduplicates
	// while preserving first-seen order.
	t.Run("comma list", func(t *testing.T) {
		t.Setenv(EnvResolvers, " 169.254.169.253 , 8.8.8.8 ,not-an-ip, 8.8.8.8 ,1.1.1.1")
		got, requested := resolverListFromEnv()
		want := []string{"169.254.169.253", "8.8.8.8", "1.1.1.1"}
		if !requested {
			t.Fatal("comma list: requested = false, want true")
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("comma list: got %v, want %v", got, want)
		}
	})

	// Set but nothing valid: requested is true so the caller can warn, list is
	// empty so the caller falls back to the baseline.
	t.Run("set but invalid", func(t *testing.T) {
		t.Setenv(EnvResolvers, "nope, also-nope")
		got, requested := resolverListFromEnv()
		if !requested {
			t.Fatal("invalid: requested = false, want true")
		}
		if len(got) != 0 {
			t.Fatalf("invalid: got %v, want empty", got)
		}
	})

	// File path: one IP per line, blank lines and '#' comments ignored.
	t.Run("file path", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "resolvers.txt")
		content := "# trusted resolvers\n169.254.169.253\n\n8.8.8.8\n  1.1.1.1  \n# trailing comment\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write temp file: %v", err)
		}
		t.Setenv(EnvResolvers, path)
		got, requested := resolverListFromEnv()
		want := []string{"169.254.169.253", "8.8.8.8", "1.1.1.1"}
		if !requested {
			t.Fatal("file path: requested = false, want true")
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("file path: got %v, want %v", got, want)
		}
	})
}

func TestResolverPoolQPS(t *testing.T) {
	cases := []struct {
		val  string
		want int
	}{
		{"", 0},
		{"0", 0},
		{"800", 800},
		{"-5", 0},
		{"notanumber", 0},
		{"  1200 ", 1200},
	}
	for _, c := range cases {
		t.Setenv(EnvResolverQPS, c.val)
		if got := resolverPoolQPS(); got != c.want {
			t.Errorf("resolverPoolQPS(%q) = %d, want %d", c.val, got, c.want)
		}
	}
}

func TestWildcardResolver(t *testing.T) {
	cases := []struct {
		val  string
		want string
	}{
		{"", defaultWildcardResolver},
		{"not-an-ip", defaultWildcardResolver},
		{"169.254.169.253", "169.254.169.253"},
		{"  1.1.1.1 ", "1.1.1.1"},
	}
	for _, c := range cases {
		t.Setenv(EnvWildcardResolver, c.val)
		if got := wildcardResolver(); got != c.want {
			t.Errorf("wildcardResolver(%q) = %q, want %q", c.val, got, c.want)
		}
	}
}
