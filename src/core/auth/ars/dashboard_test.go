package ars

import (
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
