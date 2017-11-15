package token

import (
	"fmt"
	"strings"

	"gopkg.in/mgo.v2/bson"

	"github.com/docker/distribution/registry/auth/token"
	"github.com/vmware/harbor/src/common/mongo"
	"github.com/vmware/harbor/src/common/utils/log"
	"github.com/vmware/harbor/src/ui/appconfig"
	"github.com/vmware/harbor/src/ui/auth/arrowcloud"
)

// authutils#FilterAccess checks permission against namespace (project) as standard auth server does.
// FilterPushAccessByApp filters push access based on arrowcloud app settings.
// * If the image name corresponds to an app name in arrowcloud db checks if the user has write
// permission on the app.
// * If the image name does not correspond to an app name in arrowcloud db and APP_ONLY is true
// push will be denied. Otherwise, push is granted.
func FilterPushAccessByApp(username string, a *token.ResourceActions) {

	if !appconfig.AppCheck() {
		log.Warningf("skip checking arrowcloud app for push access.")
		return
	}

	if a.Type == "registry" && a.Name == "catalog" {
		log.Infof("current access, type: %s, name:%s, actions:%v \n", a.Type, a.Name, a.Actions)
		return
	}

	canPush := false // if push is allowed based on registry_auth db
	index := 0       // index of "push" in a.Actions array
	for i, action := range a.Actions {
		if action == "push" {
			canPush = true
			index = i
			break
		}
	}
	if !canPush { // push not allowed based on registry_auth db. No need to check more.
		log.Debugf("Push is not allowed based on registry_auth db. No need to check arrowcloud app.")
		return
	}

	repoSplit := strings.Split(a.Name, "/")
	repoLength := len(repoSplit)
	if repoLength > 1 {
		newCanPush, err := checkPushPermission(repoSplit[0], repoSplit[1], username)
		if err != nil {
			log.Errorf("error checking push permission for repo %s. %v", a.Name, err)
			newCanPush = false
		}
		if !newCanPush {
			log.Debugf("cannot push according to arrowcloud app check")
			a.Actions = append(a.Actions[:index], a.Actions[index+1:]...)
		}
		log.Debugf("current access, type: %s, name:%s, actions:%v \n", a.Type, a.Name, a.Actions)
	}
}

// An app document in arrowcloud database
// {
// 	"_id" : ObjectId("586b6bb34d1afb0022701395"),
// 	"userid" : ObjectId("586b16bf3ad59899c6f1aa63"),
// 	"email" : "yjin@appcelerator.com",
// 	"name" : "abc",
// 	"deployid" : "df1d6a375f9416e23aba5b2685c014edb2f15bf7",
// 	"created_at" : ISODate("2017-01-03T09:15:31.849Z"),
// 	"status" : "notPublished",
// 	"server_size" : "Dev",
// 	"orgid" : "14301"
// }
// CheckPushPermission determines if "push" permission should be granted based on organization settings
// projectName: organization id
// imageName: image name (should be same as an app name if APP_ONLY is true)
func checkPushPermission(projectName, imageName, userEmail string) (bool, error) {

	log.Debugf("check push permission by arrowcloud app. org: %s, app: %s, user: %s", projectName, imageName, userEmail)
	userQ := bson.M{
		"email": userEmail,
	}
	users := []bson.M{}
	err := mongo.FindDocuments(arrowcloud.ARROW_CLOUD_USERS_COLL, userQ, nil, nil, &users)
	if err != nil {
		return false, err
	}
	if len(users) == 0 {
		return false, fmt.Errorf("user %s not found", userEmail)
	}
	user := users[0]
	userID := user["_id"].(bson.ObjectId)
	// {
	// 	"_id" : ObjectId("58690bd71fe0c733b70d4cac"),
	// 	"guid" : "e5fd038ab0ddf6bf04479e289e38141c",
	// 	"email" : "yjin@appcelerator.com",
	// 	"username" : "yjin@appcelerator.com",
	// 	"firstname" : "Yuping",
	// 	"orgs_360" : [
	// 		{
	// 			"id" : "14301",
	// 			"name" : "appcelerator Inc.",
	// 			"admin" : true,
	// 			"node_acs_admin" : true
	// 		}
	// 	],
	// 	"orgs_360_updated_at" : ISODate("2017-01-01T14:01:59.274Z")
	// }
	orgs := user["orgs_360"].([]interface{})
	roleByID := map[string]bool{} //role per organization
	for _, orgI := range orgs {
		org := orgI.(bson.M)
		orgID := org["id"].(string)
		roleByID[orgID] = org["node_acs_admin"].(bool)
	}

	// try to find an app by using imageName as app name
	appQ := bson.M{
		"name": imageName, //imageName should be same as app name
		"$or": []interface{}{
			bson.M{
				"userid": userID,
			},
			bson.M{
				"orgid": projectName, //projectName is orgid
			},
		},
	}

	apps := []bson.M{}
	err = mongo.FindDocuments(arrowcloud.ARROW_CLOUD_APPS_COLL, appQ, nil, nil, &apps)
	if err != nil {
		return false, err
	}

	//can only push images which have corresponding apps
	appOnly := appconfig.AppOnly()
	if len(apps) == 0 {
		if appOnly {
			log.Debugf("It's not allowed to push images which don't have corresponding arrowcloud apps.")
			return false, nil
		}
		log.Debugf("No arrowcloud app exists, but push is allowed.")
		return true, nil
	}

	app := apps[0]
	//user's own app
	if (app["userid"].(bson.ObjectId)).String() == userID.String() {
		log.Debugf("This image is for user's own app. Push is allowed.")
		return true, nil
	}
	//org's app created by others. User should be org admin to push.
	for orgID, role := range roleByID {
		if orgID == projectName {
			log.Debugf("This image is for someone else's app. allowed: %v", role)
			return role, nil //role indicates user is admin or not
		}
	}
	return false, nil
}
