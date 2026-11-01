// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"log/slog"
	"strings"
	"sync"
	"unicode"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Role names are what a WHOIS or RDAP contact is called when it is a job
// rather than a person or company: "Domain Administrator", "Hostmaster",
// "DNS Admin", "IT Department". Thousands of unrelated registrants use the
// same ones, so an organization named after a role links all of them, the
// way a shared address does. A name is a role name when every word is from
// roleWords and at least one is from roleHeadWords; any other word (a
// company name, "Inc", "Ltd") makes it a real name.
//
// Non-names are the same problem from the other side: values a registry or
// a certificate puts where no organization exists ("N/A", "None", "Private
// Person" for every RU-CENTER individual, "Internet Widgits Pty Ltd" in
// every default OpenSSL certificate). They are matched as whole values, and
// a value with no letters or digits at all ("-", ".") is one too.
var (
	roleHeadWords = map[string]struct{}{}
	roleWords     = map[string]struct{}{}
)

func init() {
	for _, w := range []string{
		"admin", "admins", "administrator", "administrators", "adminstrator",
		"administration", "administrative", "manager", "managers", "management",
		"master", "webmaster", "hostmaster", "postmaster", "sysadmin", "contact",
		"contacts", "team", "department", "dept", "operations", "ops", "noc",
		"registrant", "owner", "billing", "technical", "tech", "abuse",
	} {
		roleHeadWords[w] = struct{}{}
		roleWords[w] = struct{}{}
	}
	for _, w := range []string{
		"the", "and", "of", "for", "domain", "domains", "dns", "name", "names",
		"web", "host", "hosting", "post", "mail", "email", "network", "networks",
		"net", "it", "is", "system", "systems", "sys", "internet", "registration",
		"registrations", "role", "account", "accounts",
	} {
		roleWords[w] = struct{}{}
	}
}

var nonNames = map[string]struct{}{}

func init() {
	for _, n := range []string{
		// no organization
		"n a", "na", "none", "null", "nil", "nothing", "unknown", "not applicable",
		"not available", "not provided", "none provided", "not specified", "unspecified",
		"undisclosed", "empty", "blank", "no company", "no organization", "no organisation",
		"no org", "no name", "noname", "anonymous", "test", "x", "xx", "xxx",
		// individuals rather than organizations
		"private person", "private individual", "private registrant", "private",
		"privat", "privatperson", "privatperson ohne firma", "particulier", "particular",
		"privato", "prive", "individual", "individuals", "personal", "person",
		"self", "self employed", "home", "owner",
		// defaults that certificate tools and appliances fill in
		"internet widgits pty ltd", "default company ltd", "my company", "mycompany",
		"company", "company name", "organization", "organisation", "my organization",
		"some organization", "some company", "example", "example inc",
	} {
		nonNames[n] = struct{}{}
	}
}

func nameWords(name string) []string {
	return strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// IsNonName reports whether an organization name is a placeholder that names
// no organization: "N/A", "None", "Private Person", "Internet Widgits Pty
// Ltd", or a value with no letters or digits ("-", "."). An empty value is
// not reported; callers already skip those.
func IsNonName(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	words := nameWords(name)
	if len(words) == 0 {
		return true
	}
	_, ok := nonNames[strings.Join(words, " ")]
	return ok
}

// IsGenericName reports whether a name is a role name or a non-name: either
// way, not the name of an organization, and shared by unrelated parties.
func IsGenericName(name string) bool {
	return IsRoleName(name) || IsNonName(name)
}

// IsRoleName reports whether a contact or organization name is a role name
// ("Domain Administrator", "Hostmaster", "DNS Admin") rather than the name
// of a person or organization.
func IsRoleName(name string) bool {
	words := nameWords(name)
	if len(words) == 0 {
		return false
	}

	var head bool
	for _, w := range words {
		if _, ok := roleWords[w]; !ok {
			return false
		}
		if _, ok := roleHeadWords[w]; ok {
			head = true
		}
	}
	return head
}

// IsRoleOrganization reports whether the Organization is named after a role
// or a placeholder (IsGenericName) rather than an organization.
func IsRoleOrganization(o *oamorg.Organization) bool {
	if o == nil {
		return false
	}
	if o.Name != "" {
		return IsGenericName(o.Name)
	}
	return IsGenericName(o.LegalName)
}

// session ID + organization entity ID, so each session logs a skipped
// organization once.
var roleOrgsLogged sync.Map

// SkipRoleOrganization reports whether the Organization entity is named
// after a role or a placeholder and so must not be used to expand scope,
// logging the first skip of each organization in each session.
func SkipRoleOrganization(sess et.Session, ent *dbt.Entity, plugin string) bool {
	if ent == nil {
		return false
	}
	o, ok := ent.Asset.(*oamorg.Organization)
	if !ok || !IsRoleOrganization(o) {
		return false
	}

	key := sess.ID().String() + "|" + ent.ID
	if _, logged := roleOrgsLogged.LoadOrStore(key, struct{}{}); !logged {
		sess.Log().Info("skipping organization: a role or placeholder name, not an organization",
			"organization", o.Name, slog.Group("plugin", "name", plugin))
	}
	return true
}
