package ars

import "testing"

var (
	oldOrgs = map[string]Org{
		"14301": Org{
			ID:       "14301",
			Name:     "Appcelerator Inc.",
			ARSAdmin: true,
		},
		"14302": Org{
			ID:       "14302",
			Name:     "Axway Inc.",
			ARSAdmin: false,
		},
	}
)

func TestCompareOrgMaps1(t *testing.T) {

	freshOrgs := oldOrgs

	changed, newOrgs, removedOrgs, updatedOrgs := compareOrgMaps(oldOrgs, freshOrgs)

	if changed {
		t.Errorf("should not be changed")
	}

	if len(newOrgs) > 0 {
		t.Errorf("should not have new orgs")
	}

	if len(removedOrgs) > 0 {
		t.Errorf("should not have removed orgs")
	}

	if len(updatedOrgs) > 0 {
		t.Errorf("should not have updated orgs")
	}

}

func TestCompareOrgMaps2(t *testing.T) {

	newOrg := Org{
		ID:       "14303",
		Name:     "Test Inc.",
		ARSAdmin: true,
	}
	removedOrg := Org{
		ID:       "14301",
		Name:     "Appcelerator Inc.",
		ARSAdmin: true,
	}
	updatedOrg := Org{
		ID:       "14302",
		Name:     "Axway Inc.",
		ARSAdmin: true,
	}

	freshOrgs := map[string]Org{
		"14303": newOrg,
		"14302": updatedOrg,
	}

	changed, newOrgs, removedOrgs, updatedOrgs := compareOrgMaps(oldOrgs, freshOrgs)

	if !changed {
		t.Errorf("should be changed")
	}

	if len(newOrgs) != 1 {
		t.Errorf("should have 1 new org")
	}
	if newOrgs[0] != newOrg {
		t.Errorf("wrong new org: %+v", newOrgs[0])
	}

	if len(removedOrgs) != 1 {
		t.Errorf("should have 1 removed org")
	}
	if removedOrgs[0] != removedOrg {
		t.Errorf("wrong new org: %+v", removedOrgs[0])
	}

	if len(updatedOrgs) != 1 {
		t.Errorf("should have 1 updated org")
	}
	if updatedOrgs[0] != updatedOrg {
		t.Errorf("wrong new org: %+v", updatedOrgs[0])
	}
}
