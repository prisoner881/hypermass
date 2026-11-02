// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/registry"
)

// Every plugin must register its handlers without conflicts, as the engine
// does at start-up: two exclusive handlers at the same position for the same
// event type make a plugin's Start fail, and the engine then refuses to
// start. Start-up failures for other reasons (a plugin needing the network,
// say) are reported but do not fail this test; registration conflicts do.
func TestPluginHandlersRegisterWithoutConflicts(t *testing.T) {
	r := registry.NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))

	for _, f := range pluginNewFuncs {
		p := f()
		if p == nil {
			continue
		}
		if err := p.Start(r); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "already registered") {
				t.Errorf("plugin %s: handler registration conflict: %v", p.Name(), err)
			} else {
				t.Logf("plugin %s did not start here (not a registration conflict): %v", p.Name(), err)
			}
			continue
		}
		p.Stop()
	}
}
