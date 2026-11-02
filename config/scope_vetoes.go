// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// Scope veto modes (Config.ScopeVetoes).
const (
	ScopeVetoesEnforce = "enforce"
	ScopeVetoesObserve = "observe"
	ScopeVetoesOff     = "off"
)

// ScopeVetoMode returns the scope veto mode, normalized. An empty or
// unrecognized value is "enforce": the safe choice for a setting that keeps
// scope from growing into other organizations' assets.
func (c *Config) ScopeVetoMode() string {
	switch v := strings.ToLower(strings.TrimSpace(c.ScopeVetoes)); v {
	case ScopeVetoesObserve, ScopeVetoesOff:
		return v
	default:
		return ScopeVetoesEnforce
	}
}

// loadScopeVetoSettings reads the scope_vetoes option from the YAML Options
// map.
func (c *Config) loadScopeVetoSettings(cfg *Config) error {
	v, ok := c.Options["scope_vetoes"]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("failed to parse scope_vetoes setting, value is not a string")
	}
	switch m := strings.ToLower(strings.TrimSpace(s)); m {
	case ScopeVetoesEnforce, ScopeVetoesObserve, ScopeVetoesOff:
		c.ScopeVetoes = m
	default:
		return fmt.Errorf("invalid scope_vetoes setting %q: use enforce, observe or off", s)
	}
	return nil
}
