// Copyright 2018 Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/rbac"
	errutil "github.com/goharbor/harbor/src/common/utils/error"
	"github.com/goharbor/harbor/src/common/utils/log"
	"github.com/goharbor/harbor/src/core/config"
	"github.com/goharbor/harbor/src/pkg/q"
	"github.com/goharbor/harbor/src/pkg/robot"
	"github.com/goharbor/harbor/src/pkg/robot/model"
	"github.com/pkg/errors"
)

var (
	defaultRobotName = "arspull"
)

// ARSProjectAPI handles request to /api/projects/:pname/robot
type ARSProjectAPI struct {
	BaseController
	project *models.Project
	ctr     robot.Controller
}

// Prepare validates the URL and the user
func (p *ARSProjectAPI) Prepare() {
	p.BaseController.Prepare()

	projectName := p.GetStringFromPath(":pname")
	if len(projectName) != 0 {
		log.Debugf("finding project %s...", projectName)
		project, err := p.ProjectMgr.Get(projectName)
		if err != nil {
			p.ParseAndHandleError(fmt.Sprintf("failed to get project %s", projectName), err)
			return
		}
		if project == nil {
			log.Debugf("project %s not found", projectName)
		}
		p.project = project
	}
	p.ctr = robot.RobotCtr
}

func (p *ARSProjectAPI) requireAccess(action rbac.Action, subresource ...rbac.Resource) bool {
	if len(subresource) == 0 {
		subresource = append(subresource, rbac.ResourceSelf)
	}

	return p.RequireProjectAccess(p.project.ProjectID, action, subresource...)
}

// InitProject a project to create a default robot account ...
// beego.Router("/api/projects/:pname/robot", &api.ARSRobotAPI{}, "post:InitProject")
func (p *ARSProjectAPI) InitProject() {

	if !p.SecurityCtx.IsAuthenticated() {
		p.SendUnAuthorizedError(errors.New("Unauthorized"))
		return
	}
	var onlyAdmin bool
	var err error

	onlyAdmin, err = config.OnlyAdminCreateProject()
	if err != nil {
		log.Errorf("failed to determine whether only admin can create projects: %v", err)
		p.SendInternalServerError(fmt.Errorf("failed to determine whether only admin can create projects: %v", err))
		return
	}

	if onlyAdmin && !(p.SecurityCtx.IsSysAdmin() || p.SecurityCtx.IsSolutionUser()) {
		log.Errorf("Only sys admin can create project")
		p.SendForbiddenError(errors.New("Only system admin can create project"))
		return
	}

	// If the project exists proceed to get the default robot account
	// otherwise create the project first

	// exist, err := p.ProjectMgr.Exists(pro.Name)
	// if err != nil {
	// 	p.ParseAndHandleError(fmt.Sprintf("failed to check the existence of project %s",
	// 		pro.Name), err)
	// 	return
	// }
	// if exist {
	// 	p.SendConflictError(errors.New("conflict project"))
	// 	return
	// }
	projectName := p.GetStringFromPath(":pname")
	var projectID int64

	if p.project == nil {

		log.Debugf("Project %s does not exist. creating it...", projectName)

		isPublic := 0
		pro := &models.ProjectRequest{
			Name:     projectName,
			Metadata: map[string]string{},
			Public:   &isPublic,
		}

		owner := p.SecurityCtx.GetUsername()

		projectID, err = p.ProjectMgr.Create(&models.Project{
			Name:      pro.Name,
			OwnerName: owner,
			Metadata:  pro.Metadata,
		})
		if err != nil {
			if err == errutil.ErrDupProject {
				log.Debugf("conflict %s", pro.Name)
				p.SendConflictError(fmt.Errorf("conflict %s", pro.Name))
			} else {
				p.ParseAndHandleError("failed to add project", err)
			}
			return
		}

		project, err := p.ProjectMgr.Get(projectName)
		if err != nil {
			p.ParseAndHandleError(fmt.Sprintf("failed to get project %s", projectName), err)
			return
		}
		p.project = project
		log.Debugf("Project %s(%d) created", projectName, projectID)

	} else {
		projectID = p.project.ProjectID
		log.Debugf("Project %s(%d) exists.", projectName, projectID)
	}

	// check if the project has a default robot account. if so return it
	// otherwise creat one and return it

	keywords := make(map[string]interface{})
	keywords["ProjectID"] = projectID
	keywords["Name"] = defaultRobotName
	query := &q.Query{
		Keywords: keywords,
	}
	robots, err := p.ctr.ListRobotAccount(query)
	if err != nil {
		p.SendInternalServerError(errors.Wrap(err, "robot API: list"))
		return
	}
	if len(robots) > 0 {
		log.Debugf("default robot account found for project %s", projectName)

		p.Data["json"] = robots[0]
		p.ServeJSON()
		return
	}

	log.Debugf("default robot account not found for project %s. creating it...", projectName)

	if !p.RequireProjectAccess(projectID, rbac.ActionCreate, rbac.ResourceRobot) {
		p.SendUnAuthorizedError(errors.New("Unauthorized"))
		return
	}

	robotReq := model.RobotCreate{
		Name:        defaultRobotName,
		Description: "default robot account created by ARS for pulling images inside ARS cluster",
		Visible:     true,
		ProjectID:   projectID,
		Access: []*rbac.Policy{
			&rbac.Policy{
				Resource: rbac.Resource(fmt.Sprintf("/project/%v/repository", projectID)),
				Action:   rbac.Action("pull"),
			},
			&rbac.Policy{
				Resource: rbac.Resource(fmt.Sprintf("/project/%v/helm-chart", projectID)),
				Action:   rbac.Action("read"),
			},
		},
	}

	if err := validateRobotReq(p.project, &robotReq); err != nil {
		p.SendBadRequestError(err)
		return
	}

	robot, err := p.ctr.CreateRobotAccount(&robotReq)
	if err != nil {
		if err == dao.ErrDupRows {
			p.SendConflictError(errors.New("conflict robot account"))
			return
		}
		p.SendInternalServerError(errors.Wrap(err, "robot API: post"))
		return
	}

	w := p.Ctx.ResponseWriter
	w.Header().Set("Content-Type", "application/json")

	robotRep := model.RobotRep{
		Name:  robot.Name,
		Token: robot.Token,
	}

	p.Redirect(http.StatusCreated, strconv.FormatInt(robot.ID, 10))
	p.Data["json"] = robotRep
	p.ServeJSON()

	go func() {
		if err = dao.AddAccessLog(
			models.AccessLog{
				Username:  p.SecurityCtx.GetUsername(),
				ProjectID: projectID,
				RepoName:  projectName + "/",
				RepoTag:   "N/A",
				Operation: "init",
				OpTime:    time.Now(),
			}); err != nil {
			log.Errorf("failed to add access log: %v", err)
		}
	}()

	// p.Redirect(http.StatusCreated, strconv.FormatInt(projectID, 10))
}
