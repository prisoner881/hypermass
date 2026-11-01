// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
)

// Adding a certificate adds the registered domain of its common name;
// before, a common name naming a host added nothing.
func TestAddCertificateAddsRegisteredDomain(t *testing.T) {
	for _, c := range []struct{ cn, want string }{
		{"www.sub-co.com", "sub-co.com"},
		{"sub-co.com", "sub-co.com"},
		{"*.shop.example.co.uk", "example.co.uk"},
		{"API.Example.ORG", "example.org"},
	} {
		s := &Scope{domains: map[string]oam.Asset{}}
		if !s.Add(&oamcert.TLSCertificate{SubjectCommonName: c.cn, SerialNumber: "1"}) {
			t.Errorf("%s: want added", c.cn)
		}
		if _, ok := s.domains[c.want]; !ok || len(s.domains) != 1 {
			t.Errorf("%s: want only %s in scope, got %v", c.cn, c.want, s.domains)
		}
	}
	// a common name that is not a domain name adds nothing
	s := &Scope{domains: map[string]oam.Asset{}}
	if s.Add(&oamcert.TLSCertificate{SubjectCommonName: "Fortinet Device", SerialNumber: "2"}) || len(s.domains) != 0 {
		t.Errorf("non-domain common name: want nothing added, got %v", s.domains)
	}
}
