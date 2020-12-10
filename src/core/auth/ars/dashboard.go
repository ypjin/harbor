package ars

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils/log"

	"github.com/Jeffail/gabs"
	"github.com/goharbor/harbor/src/core/auth"
)

const (
	roleNameProjectAdmin        = "projectAdmin"
	roleNameDeveloper           = "developer"
	envVarUserOrgsCacheDuration = "USER_ORGS_CACHE_DURATION"
	envVarUserSessionDuration   = "USER_SESSION_DURATION"
)

var (
	orgsCacheDur   time.Duration
	userSessionDur time.Duration
)

// Auth implements Authenticator interface to authenticate user against Dashboard.
type Auth struct {
	auth.DefaultAuthenticateHelper
}

// Authenticate user against appcelerator 360 (dashboard). This is for enterprise user only.
func (d *Auth) Authenticate(m models.AuthModel) (*models.User, error) {

	username := m.Principal
	useToken := false
	authAgainstBackend := func(useToken bool) (*models.User, error) {
		if useToken {
			return authenticateByToken(m)
		}
		return authenticateByPassword(m)
	}

	// test if the password is a JWT token. If so it should be got from AxwayID.
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(m.Password, jwt.MapClaims{})
	if err == nil {
		log.Debug("Access token is provided, authenticating with access token...")
		useToken = true
		mapClaims := parsedToken.Claims.(jwt.MapClaims)
		username := mapClaims["preferred_username"].(string)
		log.Debugf("username got from token: %s", username)
	} else {
		log.Debug("Password is provided, authenticating with password...")
	}

	mUser := &models.User{
		Username: username,
	}
	existing, err := dao.GetUser(*mUser)
	if err != nil {
		log.Errorf("error checking user existence. %v", err)
		return nil, err
	}
	if existing == nil {
		log.Errorf("no user exists for %s", username)
		return authAgainstBackend(useToken)
	}

	log.Debugf("got existing user: %+v", existing)
	log.Debugf("existing user ResetUUID: %s", existing.ResetUUID) // time last auth happened
	log.Debugf("existing user Password: %s", existing.Password)   // password or token hash

	if existing.Password != getDegest(m.Password) {
		log.Errorf("got different password.")
		return authAgainstBackend(useToken)
	}

	authTime, err := time.Parse(time.RFC3339, existing.ResetUUID)
	if err != nil {
		log.Errorf("error parsing ResetUUID as time. %v", err)
		return authAgainstBackend(useToken)
	}
	if time.Now().After(authTime.Add(userSessionDur)) {
		log.Debugf("last auth time is earlier than %s", userSessionDur)
		return authAgainstBackend(useToken)
	}

	return existing, nil
}

func authenticateByPassword(m models.AuthModel) (*models.User, error) {

	host360 := os.Getenv("DASHBOARD_HOST")
	if len(host360) == 0 {
		host360 = "https://platform-preprod.axwaytest.net"
	}
	authPath := os.Getenv("DASHBOARD_AUTHPATH")
	if len(authPath) == 0 {
		authPath = "/api/v1/auth/login"
	}

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

	sid := getSessionID(resp, jsonBody)
	if sid == "" {
		log.Error("checkAuthResponse - bad response from Appcelerator 360: no cookie info")
		err = errors.New("bad response from Appcelerator 360: no cookie info")
		return nil, err
	}

	mUser := createUserObject(jsonBody, sid, getDegest(m.Password))

	return mUser, nil
}

func createUserObject(userData *gabs.Container, sid string, passwordHash string) *models.User {

	// use Realname field to save dashboard session and Salt for the realname.
	// No other unused fields (including Salt) are long enough for sid.
	mUser := &models.User{
		Username: userData.Path("result.username").Data().(string),
		Password: passwordHash,
		Realname: sid,
	}

	if userData.Path("result.email").Data() != nil {
		mUser.Email = userData.Path("result.email").Data().(string)
	} else if userData.Path("result.user.email").Data() != nil {
		mUser.Email = userData.Path("result.user.email").Data().(string)
	} else {
		mUser.Email = mUser.Username
	}

	var firstName, lastName string

	if userData.Path("result.firstname").Data() != nil {
		firstName = userData.Path("result.firstname").Data().(string)
	} else if userData.Path("result.user.firstname").Data() != nil {
		firstName = userData.Path("result.user.firstname").Data().(string)
	}
	if userData.Path("result.lastname").Data() != nil {
		lastName = userData.Path("result.lastname").Data().(string)
	} else if userData.Path("result.user.lastname").Data() != nil {
		lastName = userData.Path("result.user.lastname").Data().(string)
	}

	// Realname is used for saving dashboard session
	mUser.Salt = firstName + " " + lastName

	// "role": "administrator"
	// This cannot be mapped to the harbor admin role.
	// if userData.Path("result.role").Data().(string) == "administrator" {
	// 	mUser.Rolename = roleNameProjectAdmin
	// 	mUser.HasAdminRole = true
	// 	mUser.Role = 1
	// } else {
	mUser.Rolename = roleNameDeveloper
	mUser.HasAdminRole = false
	mUser.Role = 2
	// }

	// ARS-4919
	mUser.ResetUUID = time.Now().Format(time.RFC3339)
	return mUser
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

	// need to save dashboardsid in user.Realname as it's the only field long enough
	dashboardSid := user.Realname

	var cachedUserOrg *models.UserOrg
	refreshOrgs := false

	if dbUser == nil {
		log.Debugf("onboarding user: %s", user.Email)
		d.OnBoardUser(user)
		refreshOrgs = true
	} else {
		user.UserID = dbUser.UserID
		user.HasAdminRole = dbUser.HasAdminRole
		fillEmailRealName(user)
		// ResetUUID field is used for saving the time authentication happening
		if err2 := dao.ChangeUserProfile(*user, "Email", "Realname", "ResetUUID", "Password"); err2 != nil {
			log.Warningf("Failed to update user profile, user: %s, error: %v", user.Username, err2)
		}

		// if organizations were got in 5 minutes skip refreshing
		cachedUserOrg, err = dao.GetUserOrg(user.UserID)
		if err != nil {
			return err
		}

		// TODO show cachedUserOrg.UpdateTime
		log.Debugf("cachedUserOrg.UpdateTime: %v", cachedUserOrg.UpdateTime)

		if cachedUserOrg == nil {
			log.Warningf("No cached organization info found for user %s", user.Username)
			refreshOrgs = true
		} else {
			if time.Now().After(cachedUserOrg.UpdateTime.Add(orgsCacheDur)) {
				log.Debugf("The cached organization info is older than %s for user %s. need to refresh", orgsCacheDur, user.Username)
				refreshOrgs = true
			} else {
				log.Debugf("The cached organization info is not older than %s for user %s. no need to refresh", orgsCacheDur, user.Username)
			}
		}
	}

	if !refreshOrgs {
		return nil
	}

	// user.Salt keeps the session ID of dashboard
	haveAccess, freshOrgs, err := getAndVerifyOrgInfoFrom360(user.Username, dashboardSid)
	if err != nil {
		log.Error(err)
		return err
	}
	if !haveAccess {
		log.Errorf("PostAuthenticate - user's organizations do not have access to this domain")
		err = errors.New("No access to this domain")
		return err
	}

	jsonOrgs, err := json.Marshal(freshOrgs)
	if err != nil {
		log.Error(err)
		return err
	}

	// TODO set updateTime
	mUserOrg := &models.UserOrg{
		UserID: user.UserID,
		Orgs:   string(jsonOrgs),
	}

	oldOrgs := map[string]Org{}
	if cachedUserOrg == nil {
		log.Debugf("add orgs for user %s", user.Email)
		_, err = dao.AddUserOrg(mUserOrg)
		if err != nil {
			return err
		}
	} else {
		err = json.Unmarshal([]byte(cachedUserOrg.Orgs), &oldOrgs)
		if err != nil {
			return err
		}
	}

	changed, newOrgs, removedOrgs, updatedOrgs := compareOrgMaps(oldOrgs, freshOrgs)
	if !changed {
		log.Debugf("no changes in organization setting for user %s", user.Email)
		// still need to update UserOrg to refresh UpdateTime so that it does not need to get orgs from dashboard
		// upon every auth request after the cached is older than 5 mins.
		return dao.UpdateUserOrg(mUserOrg)
	}

	err = mapOrgsToProjectsAndMembers(user, newOrgs, removedOrgs, updatedOrgs)
	if err != nil {
		return err
	}

	log.Debugf("update orgs for user %s", user.Email)
	err = dao.UpdateUserOrg(mUserOrg)

	return err
}

// SearchUser - Check if user exist in local db
// if a user never login it should not exist in local db.
func (d *Auth) SearchUser(username string) (*models.User, error) {
	var queryCondition = models.User{
		Username: username,
	}

	return dao.GetUser(queryCondition)
}

// https://8gwifi.org/docs/go-hashing.jsp
// https://gist.github.com/sergiotapia/8263278
func getDegest(value string) string {
	// The pattern for generating a hash is `sha1.New()`,
	// `sha1.Write(bytes)`, then `sha1.Sum([]byte{})`.
	// Here we start with a new hash.
	h := sha256.New()

	// `Write` expects bytes. If you have a string `s`,
	// use `[]byte(s)` to coerce it to bytes.
	h.Write([]byte(value))

	// This gets the finalized hash result as a byte
	// slice. The argument to `Sum` can be used to append
	// to an existing byte slice: it usually isn't needed.
	bs := h.Sum(nil)

	// SHA1 values are often printed in hex, for example
	// in git commits. Use the `%x` format verb to convert
	// a hash results to a hex string.
	// fmt.Println(s)
	return fmt.Sprintf("%x", bs)
}

func getConfiguredDuration(envVarName string, defValue time.Duration) time.Duration {

	desiredDur := defValue

	configuredDurString := os.Getenv(envVarName)
	if configuredDurString != "" {
		configuredDur, err := time.ParseDuration(configuredDurString)
		if err != nil {
			log.Warningf("invalid %s %s. will be ignored", envVarName, configuredDurString)
		} else {
			desiredDur = configuredDur
			log.Debugf("%s: %v", envVarName, configuredDur)
		}
	}

	return desiredDur
}

func init() {
	auth.Register(common.ARSDashboardAuth, &Auth{})

	orgsCacheDur = getConfiguredDuration(envVarUserOrgsCacheDuration, 5*time.Minute)
	userSessionDur = getConfiguredDuration(envVarUserSessionDuration, 2*time.Minute)
}
