// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"testing"
)

func TestScopeVetoMode(t *testing.T) {
	for in, want := range map[string]string{
		"": "enforce", "enforce": "enforce", "ENFORCE": "enforce", " observe ": "observe",
		"off": "off", "bogus": "enforce",
	} {
		c := NewConfig()
		c.ScopeVetoes = in
		if got := c.ScopeVetoMode(); got != want {
			t.Errorf("%q: mode %q, want %q", in, got, want)
		}
	}
}

func TestLoadScopeVetoSettings(t *testing.T) {
	c := NewConfig()
	c.Options = map[string]interface{}{"scope_vetoes": "Observe"}
	if err := c.loadScopeVetoSettings(c); err != nil || c.ScopeVetoes != "observe" {
		t.Fatalf("observe: got %q, %v", c.ScopeVetoes, err)
	}
	c.Options = map[string]interface{}{"scope_vetoes": "sometimes"}
	if err := c.loadScopeVetoSettings(c); err == nil {
		t.Error("invalid value: want an error")
	}
	c.Options = map[string]interface{}{"scope_vetoes": true}
	if err := c.loadScopeVetoSettings(c); err == nil {
		t.Error("non-string value: want an error")
	}
}

// The setting reaches the engine with the session config, which is JSON.
func TestScopeVetoesJSON(t *testing.T) {
	c := NewConfig()
	c.ScopeVetoes = "observe"
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.ScopeVetoMode() != "observe" {
		t.Errorf("after JSON: mode %q, want observe", back.ScopeVetoMode())
	}
}
