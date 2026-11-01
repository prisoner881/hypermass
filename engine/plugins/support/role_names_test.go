// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestIsRoleName(t *testing.T) {
	for _, name := range []string{
		"Domain Administrator",
		"domain adminstrator", // as Salesforce's WHOIS spells it
		"DOMAIN ADMIN",
		"Hostmaster",
		"DNS Admin",
		"Domain Manager",
		"IT Department",
		"Network Operations",
		"Webmaster",
		"Technical Contact",
		"The Domain Name Administrator",
		"Domain Names Administration",
		"Billing",
		"Registrant",
	} {
		if !IsRoleName(name) {
			t.Errorf("%q: want role name", name)
		}
	}
	for _, name := range []string{
		"",
		"Salesforce, Inc.",
		"Crayon AS",
		"Domain Management Ltd",
		"Network Solutions, LLC",
		"Hostmaster Ltd",
		"Admin Corp",
		"John Smith",
		"Domain", // no role word
		"DNS",
		"admin@example.com",
		"Blue Express S.A.",
	} {
		if IsRoleName(name) {
			t.Errorf("%q: want a real name", name)
		}
	}
}

func TestSkipRoleOrganization(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sess := &sharedLocTestSession{id: uuid.New(), db: db}
	ctx := context.Background()

	role, err := db.CreateAsset(ctx, &oamorg.Organization{ID: uuid.NewString(), Name: "domain adminstrator"})
	if err != nil {
		t.Fatal(err)
	}
	real, err := db.CreateAsset(ctx, &oamorg.Organization{ID: uuid.NewString(), Name: "Salesforce, Inc."})
	if err != nil {
		t.Fatal(err)
	}
	if !SkipRoleOrganization(sess, role, "test") || !SkipRoleOrganization(sess, role, "test") {
		t.Error("domain adminstrator: want skipped on every check")
	}
	if SkipRoleOrganization(sess, real, "test") {
		t.Error("Salesforce, Inc.: want not skipped")
	}
	if SkipRoleOrganization(sess, nil, "test") {
		t.Error("nil: want not skipped")
	}
}

// Non-names name no organization; each is shared by unrelated registrants
// or devices, like a role name.
func TestIsNonName(t *testing.T) {
	for _, name := range []string{
		"N/A", "n/a", "NA", "None", "NULL", "Unknown", "Not Applicable", "-", ".", "--",
		"Private Person", "PRIVATE PERSON", "Individual", "Personal", "Private",
		"Internet Widgits Pty Ltd", "Default Company Ltd", "MyCompany", "My Company",
	} {
		if !IsNonName(name) || !IsGenericName(name) {
			t.Errorf("%q: want non-name", name)
		}
	}
	for _, name := range []string{
		"", "   ", "Crayon AS", "Salesforce, Inc.", "Private Equity Partners LLC",
		"Personal Capital Corporation", "Unknown Worlds Entertainment", "None Such Records",
		"Individual Retirement Services Inc", "Widgits Pty Ltd", "NA Holdings",
	} {
		if IsNonName(name) {
			t.Errorf("%q: want a real name", name)
		}
	}
}
