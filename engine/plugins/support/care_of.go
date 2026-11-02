// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"regexp"
	"strings"
)

// A care-of or mail-drop address states, in its own text, that it belongs to
// someone other than the party named with it: "Acme Corp, c/o The
// Corporation Trust Company, 1209 Orange St" is a registered agent's
// address, "1928 E. Highland Ave. Ste F104 PMB# 255" is a mail drop. Such an
// address says nothing about who the registrant is, so it must not link
// records together. The name and email beside it can still be real.
var (
	careOfRE = regexp.MustCompile(`(^|[\s,;(/])(c/o|c\\o|c\.o\.|care of)(\s|$|[,:])`)
	// a private mailbox number ("PMB 255", "PMB# 255", "private mailbox 9")
	privateMailboxRE = regexp.MustCompile(`\b(pmb|private mail ?box)\s*#?\s*\d+`)
	// a mailbox number of five or more digits after a "#", as mail-drop
	// services issue ("9450 SW Gemini Dr #63259"); suites rarely run that long
	mailboxNumberRE = regexp.MustCompile(`#\s*\d{5,}\b`)
)

// IsCareOfOrMailDrop reports whether an address or organization field is a
// care-of or mail-drop address rather than the registrant's own.
func IsCareOfOrMailDrop(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	return careOfRE.MatchString(s) || privateMailboxRE.MatchString(s) || mailboxNumberRE.MatchString(s)
}
