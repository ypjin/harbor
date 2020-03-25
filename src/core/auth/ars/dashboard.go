package ars

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils/log"

	"github.com/Jeffail/gabs"
	"github.com/goharbor/harbor/src/core/auth"
)

const (
	host360              = "https://platform-preprod.axwaytest.net"
	authPath             = "/api/v1/auth/login"
	logoutPath           = "/api/v1/auth/logout"
	orgInfoPath          = "/api/v1/user/organizations"
	thisEnvAdminURL      = "http://admin.cloudapp-1.appctest.com"
	roleNameProjectAdmin = "projectAdmin"
	roleNameDeveloper    = "developer"
)

// Auth implements Authenticator interface to authenticate user against Dashboard.
type Auth struct {
	auth.DefaultAuthenticateHelper
}

// Authenticate user against appcelerator 360 (dashboard). This is for enterprise user only.
func (d *Auth) Authenticate(m models.AuthModel) (*models.User, error) {

	loginURL := host360 + authPath
	log.Debugf("Login user %s using password against %s...", m.Principal, loginURL)

	username := m.Principal
	creds := url.Values{}
	creds.Set("username", username)
	creds.Add("password", m.Password)
	// v.Encode() == "name=Ava&friend=Jess&friend=Sarah&friend=Zoe"

	//curl -i -b cookies.txt -c cookies.txt -F "username=mgoff@appcelerator.com" -F "password=food" http://360-dev.appcelerator.com/api/v1/auth/login
	/*
	   response for bad username/password
	   HTTP/1.1 400 Bad Request
	   X-Powered-By: Express
	   Access-Control-Allow-Origin: *
	   Access-Control-Allow-Methods: GET, POST, DELETE, PUT
	   Access-Control-Allow-Headers: Content-Type, api_key
	   Content-Type: application/json; charset=utf-8
	   Content-Length: 79
	   Date: Fri, 19 Apr 2013 01:25:24 GMT
	   Connection: keep-alive
	   {"success":false,"description":"Invalid password.","code":400,"internalCode":2}
	*/
	resp, err := http.PostForm(loginURL, creds)

	if err != nil {
		log.Errorf("Failed to login to dashboard. %v", err)
		return nil, err
	}

	if resp.StatusCode != 200 {
		log.Debugf("dashboard returns status %s", resp.Status)
		return nil, errors.New("authentication failed")
	}

	bodyBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("Failed to read response body. %v", err)
		return nil, err
	}

	jsonBody, err := gabs.ParseJSON(bodyBuf)
	if err != nil {
		log.Errorf("Failed to parse response body. %v", err)
		return nil, err
	}

	// HTTP/1.1 200 OK
	// Vary: X-HTTP-Method-Override, Accept-Encoding
	// Set-Cookie: org_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT
	// Set-Cookie: guid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT
	// Set-Cookie: org_id=100001626; Domain=.axwaytest.net; Path=/; Expires=Tue, 31 Mar 2020 08:14:27 GMT; HttpOnly
	// Set-Cookie: guid=132203bc-e6dc-460f-b46d-5c9f34464730; Domain=.axwaytest.net; Path=/; Expires=Tue, 31 Mar 2020 08:14:27 GMT; HttpOnly
	// Set-Cookie: connect.sid=s%3AWWoBlskHC20P-kQuMQYgwKETK8SAH0ib.meeH%2Bg1xgPh6LBC9ysyIUDgpb5WGLxxgK1qnmB5Bpm8; Domain=.axwaytest.net; Path=/; HttpOnly
	// ...
	// {
	// 	"result": {
	// 		"success": true,
	// 		"acsAppEndpoint": "https://preprod-api.cloud.appctest.com/v1/apps/create.json?ct=enterprise",
	// 		"acsAuthBaseUrl": "",
	// 		"acsBaseUrl": "https://preprod-api.cloud.appctest.com",
	// 		"acsLoginEndpoint": "https://preprod-api.cloud.appctest.com/v1/admins/studio_login.json?ct=enterprise",
	// 		"nodeACSEndpoint": "https://admin.cloudapp-enterprise-preprod.appctest.com",
	// 		"clusterType": "enterprise",
	// 		"dashboard": "https://platform.axwaytest.net/",
	// 		"user_guid": "132203bc-e6dc-460f-b46d-5c9f34464730",
	// 		"guid": "132203bc-e6dc-460f-b46d-5c9f34464730",
	// 		"username": "yjin@appcelerator.com"
	// 		"email": "yjin@appcelerator.com",
	// 		"firstname": "Yuping",
	// 		"lastname": "Jin",
	// 		"phone": "",
	// 		"role": "administrator",
	// 		"roles": [
	// 			"administrator",
	// 			"ars_admin"
	// 		],
	// 		"org_id": 100001626,
	// 		"org_name": "ACS Emails",
	// 		"packageId": "54d8e4abce78815d81104cb4",
	// 		"entitlements": {
	// 			"_governance": {
	// 				"Axway Cloud": {
	// 					"apiRateMonth": 2000000,
	// 					"containerPoints": 1000,
	// 					"daysDataRetained": 1080,
	// 					"eventRateMonth": 1000000,
	// 					"pushRateMonth": 8640000,
	// 					"storageDatabaseGB": 100,
	// 					"storageFilesGB": 100
	// 				}
	// 			},
	// 			"_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfZ292ZXJuYW5jZSI6eyJBeHdheSBDbG91ZCI6eyJhcGlSYXRlTW9udGgiOjIwMDAwMDAsInB1c2hSYXRlTW9udGgiOjg2NDAwMDAsInN0b3JhZ2VGaWxlc0dCIjoxMDAsInN0b3JhZ2VEYXRhYmFzZUdCIjoxMDAsImNvbnRhaW5lclBvaW50cyI6MTAwMCwiZXZlbnRSYXRlTW9udGgiOjEwMDAwMDAsImRheXNEYXRhUmV0YWluZWQiOjEwODB9fSwiYXBpUmF0ZU1vbnRoIjoyMDAwMDAwLCJwdXNoUmF0ZU1vbnRoIjo4NjQwMDAwLCJzdG9yYWdlRmlsZXNHQiI6MTAwLCJzdG9yYWdlRGF0YWJhc2VHQiI6MTAwLCJjb250YWluZXJQb2ludHMiOjEwMDAsImFycm93UHVibGlzaCI6dHJ1ZSwiZXZlbnRSYXRlTW9udGgiOjEwMDAwMDAsImRheXNEYXRhUmV0YWluZWQiOjEwODAsImFsbG93UHJvZHVjdGlvbiI6dHJ1ZSwiYXBwRGVzaWduZXIiOnRydWUsImFwcFByZXZpZXciOnRydWUsImh5cGVybG9vcCI6dHJ1ZSwibmF0aXZlU0RLIjp0cnVlLCJwcmVtaXVtTW9kdWxlcyI6dHJ1ZSwiY3VzdG9tUXVlcnkiOnRydWUsInBhaWRTdXBwb3J0Ijp0cnVlLCJjb2xsYWJvcmF0aW9uIjp0cnVlLCJhbGxvd0NoaWxkT3JncyI6dHJ1ZSwicGFydG5lcnMiOlsiYWNhIiwiYWNzIiwiYW5hbHl0aWNzIl0sImVudGVycHJpc2VFdWxhIjp0cnVlLCJfdmVyc2lvbiI6MX0.DBnRsqW5_xGWYtckRn-T4mgv3AmXfuKrEzRbtPJB-2g",
	// 			"_version": 1,
	// 			"allowChildOrgs": true,
	// 			"allowProduction": true,
	// 			"apiRateMonth": 2000000,
	// 			"appDesigner": true,
	// 			"appPreview": true,
	// 			"arrowPublish": true,
	// 			"collaboration": true,
	// 			"containerPoints": 1000,
	// 			"customQuery": true,
	// 			"daysDataRetained": 1080,
	// 			"enterpriseEula": true,
	// 			"eventRateMonth": 1000000,
	// 			"hyperloop": true,
	// 			"nativeSDK": true,
	// 			"paidSupport": true,
	// 			"partners": [
	// 				"aca",
	// 				"acs",
	// 				"analytics"
	// 			],
	// 			"premiumModules": true,
	// 			"pushRateMonth": 8640000,
	// 			"storageDatabaseGB": 100,
	// 			"storageFilesGB": 100
	// 		},
	// 		"expiry": 1585705821568,
	// 		"session": "3b3f8d6b4ac6ec71e6b819e4c4d13c207a5ae9bb R4V0LYc7+PyyGolsBEUd2aFiDzNb3WZ6nCgI0HbZeN1Pmtz9yxrUoKb6nGAMTQRDVSvyZNsZOBu508HFdvqGN15d6gnwxhEarNgrHNizRuSBN2xdsIkJOHE1dxdUFoqOLbUOdgcXefpmwZZvG7H6ls7DtN0m+TikvdFrHQb2eXZt2lEYj/zpZiBDUWe5UyFIzTOvKeJnArJypU6e0WZRBu9NZH6122AjOjda6ZCIvTtko7IkdA3CGXqDk8Xr80gQbQAMIECDGmQ1XH9VfBNqpVKqsKbUC0/ox5aomDP8pUoDsubQnjhLU8nxo2fTjekRS5VYxSyqPxNL0uXfR+G+FKlKFkpwWOFnyPoKfAceec6WRtxenEVq62GI5D8aI97KlIppcCyUJoERFQccUJZ5oseUmTMlPrtlMj1nO89rO7lNN5+EM/p5HnyUC8JNeuStdfknA6axWV4YlctOT0hVX3ZK2/kj/X7cAcGJvA0DVDttEtiLFsY3wzFZ4XLY5ufin0zSwPtGhVJUAbxyAqiieV+eZrkmlFt7ud7D8vdZjdIJxZwUMBEwddPamPwcJY85nclPLgcRTUyMoiiGqzqYG0l1N2k8/d/Pd3DbJuUrJRQRCzhc/6S0ybb2zzbYMQvjcjP8xpU+/V8bfAD8JV2EGY8eze1uvYq+3Vo6g0t6HkjGIo3WHut6/7stvW6mqVWJgQRqkTjxO0Sl2eKgXBKRkg==",
	// 		"sid": "s:V2KdW9WJqz2H2gVjR1nbSwDJ2LWSQz09.HlHjOmL51f9DNL7L1lXF66IOgsNtPT+YOUXPrH4cdTw",
	// 		"connect.sid": "s:V2KdW9WJqz2H2gVjR1nbSwDJ2LWSQz09.HlHjOmL51f9DNL7L1lXF66IOgsNtPT+YOUXPrH4cdTw",
	// 		"teams": [],
	// 	},
	// 	"success": true
	// }

	success := jsonBody.Path("success").Data().(bool)
	if !success {
		log.Error("dashboard returns false for success field")
		return nil, errors.New("authentication failed")
	}

	mUser := &models.User{
		Username: jsonBody.Path("result.username").Data().(string),
		Email:    jsonBody.Path("result.email").Data().(string),
		Realname: jsonBody.Path("result.firstname").Data().(string) + " " + jsonBody.Path("result.lastname").Data().(string),
	}

	// "role": "administrator"
	if jsonBody.Path("result.role").Data().(string) == "administrator" {
		mUser.Rolename = roleNameProjectAdmin
		mUser.HasAdminRole = true
		mUser.Role = 1
	} else {
		mUser.Rolename = roleNameDeveloper
		mUser.HasAdminRole = false
		mUser.Role = 2
	}

	return mUser, nil
}

// OnBoardUser will check if a user exists in user table, if not insert the user and
// put the id in the pointer of user model, if it does exist, return the user's profile.
func (d *Auth) OnBoardUser(user *models.User) error {
	user.Username = strings.TrimSpace(user.Username)
	if len(user.Username) == 0 {
		return fmt.Errorf("the Username is empty")
	}
	if len(user.Password) == 0 {
		user.Password = "1234567ab"
	}
	fillEmailRealName(user)
	user.Comment = "From Amplify Dashboard"
	return dao.OnBoardUser(user)
}

func fillEmailRealName(user *models.User) {
	if len(user.Realname) == 0 {
		user.Realname = user.Username
	}
	if len(user.Email) == 0 && strings.Contains(user.Username, "@") {
		user.Email = user.Username
	}
}

// PostAuthenticate will check if user exists in DB, if not on Board user, if he does, update the profile.
func (d *Auth) PostAuthenticate(user *models.User) error {
	dbUser, err := dao.GetUser(models.User{Email: user.Email})
	if err != nil {
		return err
	}
	if dbUser == nil {
		return d.OnBoardUser(user)
	}
	user.UserID = dbUser.UserID
	user.HasAdminRole = dbUser.HasAdminRole
	fillEmailRealName(user)
	if err2 := dao.ChangeUserProfile(*user, "Email", "Realname"); err2 != nil {
		log.Warningf("Failed to update user profile, user: %s, error: %v", user.Username, err2)
	}

	return nil
}

// SearchUser - Check if user exist in local db
// if a user never login it should not exist in local db.
func (d *Auth) SearchUser(username string) (*models.User, error) {
	var queryCondition = models.User{
		Username: username,
	}

	return dao.GetUser(queryCondition)
}

func init() {
	auth.Register("dashboard", &Auth{})
}
