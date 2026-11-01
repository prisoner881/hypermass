// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"testing"

	whoisparser "github.com/likexian/whois-parser"
)

func TestDetectRegistrantPlaceholder(t *testing.T) {
	placeholders := []string{
		// Amazon Registrar's privacy service, as seen in the crayon.co scope leak
		"On behalf of crayon.co owner",
		"On behalf of kitche.co owner",
		"On behalf of example.com technical contact",
		"On behalf of example.co.uk admin",
		"c/o whoisproxy.com, 604 Cameron Street",
		"Identity Protection Service",
		// hashed forwarding mailboxes and privacy-service mail domains
		"3c6b8f1e0a9d4b7c2e5f8a1d4c7b0e3f@headwayapp.co.whoisproxy.org",
		"0f1e2d3c4b5a69788796a5b4c3d2e1f0aa@example.com",
		"crayon.co@domainsbyproxy.com",
		"owner@privatedomain.gkg.net",
		"abc123@withheldforprivacy.com",
		// existing behavior
		"Domains By Proxy, LLC",
		"REDACTED FOR PRIVACY",
	}
	for _, v := range placeholders {
		if d := DetectRegistrantPlaceholder(v); !d.IsPlaceholder {
			t.Errorf("%q: want placeholder, got score %d (%v)", v, d.Score, d.Matches)
		}
	}

	genuine := []string{
		"Crayon AS",
		"Booking.com B.V.",
		"Behalf Inc.",
		"On behalf of the board",
		"hostmaster@crayon.com",
		"dns-admin@google.com",
		"deadbeef@example.com", // hex, but far too short to be a hash
		"proxy-team@example.com",
		"604 Cameron Street",
		"Alexandria",
		"+1.7035550100",
		"",
	}
	for _, v := range genuine {
		if d := DetectRegistrantPlaceholder(v); d.IsPlaceholder {
			t.Errorf("%q: want genuine, got placeholder score %d (%v)", v, d.Score, d.Matches)
		}
	}
}

func TestIsPrivacyMailDomain(t *testing.T) {
	for _, d := range []string{"whoisproxy.org", "crayon.co.whoisproxy.org", "domainsbyproxy.com", "privatedomain.gkg.net"} {
		if !isPrivacyMailDomain(d) {
			t.Errorf("%s: want privacy mail domain", d)
		}
	}
	for _, d := range []string{"notwhoisproxy.org", "whoisproxy.org.example.com", "gkg.net", "example.com"} {
		if isPrivacyMailDomain(d) {
			t.Errorf("%s: want ordinary mail domain", d)
		}
	}
}

// Every contact role is screened, so a proxy's admin or technical contact
// (which carries the same shared address) is caught too.
func TestHasPlaceholdersAnyField(t *testing.T) {
	r := &domrec{}
	proxy := &whoisparser.Contact{
		Name:         "On behalf of crayon.co owner",
		Organization: "c/o whoisproxy.com",
		Street:       "604 Cameron Street",
		City:         "Alexandria",
		Province:     "VA",
		Email:        "3c6b8f1e0a9d4b7c2e5f8a1d4c7b0e3f@crayon.co.whoisproxy.org",
	}
	if !r.hasPlaceholders(proxy) {
		t.Error("whoisproxy contact: want placeholder")
	}
	real := &whoisparser.Contact{
		Name:         "Hostmaster",
		Organization: "Crayon AS",
		Street:       "Gullhaug Torg 5",
		City:         "Oslo",
		Email:        "hostmaster@crayon.com",
	}
	if r.hasPlaceholders(real) {
		t.Error("Crayon AS contact: want genuine")
	}
}
