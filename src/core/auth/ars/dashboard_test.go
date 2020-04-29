package ars

import (
	"encoding/json"
	"testing"

	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils/log"
)

func TestAuthenticateSuccess(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	somebody := models.AuthModel{
		Principal: "yjin@appcelerator.com",
		Password:  "lvfeng",
	}

	dashboard := &Auth{}

	user, err := dashboard.Authenticate(somebody)

	if err != nil {
		t.Errorf("failed to authenticate user against dashboard. %v", err)
		t.Fail()
	}

	log.Infof("got user back from dashboard: %+v", user)

	// Ω(err).ShouldNot(HaveOccurred())
	// Ω(user.Username).Should(Equal("yjin@appcelerator.com"))
	// Ω(user.Email).Should(Equal("yjin@appcelerator.com"))
	// Ω(user.Realname).Should(Equal("Yuping Jin"))
	// Ω(user.Deleted).Should(BeFalse())
	// Ω(user.Rolename).Should(Equal(roleNameProjectAdmin))
	// Ω(user.Role).Should(Equal(1))
	// Ω(user.HasAdminRole).Should(BeTrue())
}

func TestAuthenticateFailure(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	somebody := models.AuthModel{
		Principal: "test",
		Password:  "123456",
	}

	dashboard := &Auth{}

	_, err := dashboard.Authenticate(somebody)

	if err == nil {
		t.Errorf("didn't get expected err. response status code should be 400 Bad Request")
		t.Fail()
	}

}

func TestJSONField(t *testing.T) {

	freshOrgs := map[string]Org{
		"14301": Org{
			ID:       "14301",
			Name:     "Appcelerator Inc.",
			ARSAdmin: true,
		},
	}

	jsonOrgs, err := json.Marshal(freshOrgs)
	if err != nil {
		t.Error(err)
		return
	}

	mUserOrg := &models.UserOrg{
		UserID: 1,
		Orgs:   string(jsonOrgs),
	}

	oldOrgs := map[string]Org{}
	err = json.Unmarshal([]byte(mUserOrg.Orgs), &oldOrgs)
	if err != nil {
		t.Error(err)
	}

	if freshOrgs["14301"] != oldOrgs["14301"] {
		t.Errorf("error reading JSON field. %+v", oldOrgs)
	}
}
