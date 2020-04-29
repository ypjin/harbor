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
	"errors"
	"net/http"
	"strconv"

	common_job "github.com/goharbor/harbor/src/common/job"
	"github.com/goharbor/harbor/src/core/api/models"
)

// RegSyncAPI handles request of harbor registry synchonization...
type RegSyncAPI struct {
	AJAPI
}

// Prepare validates the URL and parms, it needs the system admin permission.
func (rs *RegSyncAPI) Prepare() {
	rs.BaseController.Prepare()
	if !rs.SecurityCtx.IsAuthenticated() {
		rs.SendUnAuthorizedError(errors.New("UnAuthorized"))
		return
	}
	if !rs.SecurityCtx.IsSysAdmin() {
		rs.SendForbiddenError(errors.New(rs.SecurityCtx.GetUsername()))
		return
	}
}

// Post according to the request, it creates a cron schedule or a manual trigger for registry synchonization.
// create a daily schedule for registry synchonization
// 	{
//  "schedule": {
//    "type": "Daily",
//    "cron": "0 0 0 * * *"
//  }
//	}
// create a manual trigger for registry synchonization
// 	{
//  "schedule": {
//    "type": "Manual"
//  }
//	}
func (rs *RegSyncAPI) Post() {
	ajr := models.AdminJobReq{}
	isValid, err := rs.DecodeJSONReqAndValidate(&ajr)
	if !isValid {
		rs.SendBadRequestError(err)
		return
	}
	ajr.Name = common_job.SyncRegistry
	rs.submit(&ajr)
	rs.Redirect(http.StatusCreated, strconv.FormatInt(ajr.ID, 10))
}

// Put handles registry synchonization cron schedule update/delete.
// Request: delete the schedule of registry synchonization
// 	{
//  "schedule": {
//    "type": "None",
//    "cron": ""
//  }
//	}
func (rs *RegSyncAPI) Put() {
	ajr := models.AdminJobReq{}
	isValid, err := rs.DecodeJSONReqAndValidate(&ajr)
	if !isValid {
		rs.SendBadRequestError(err)
		return
	}
	ajr.Name = common_job.SyncRegistry
	rs.updateSchedule(ajr)
}

// GetRegSyncJob ...
func (rs *RegSyncAPI) GetRegSyncJob() {
	id, err := rs.GetInt64FromPath(":id")
	if err != nil {
		rs.SendInternalServerError(errors.New("need to specify registry synchronization job id"))
		return
	}
	rs.get(id)
}

// List returns the top 10 executions of registry synchonization which includes manual and cron.
func (rs *RegSyncAPI) List() {
	rs.list(common_job.SyncRegistry)
}

// Get gets registry synchonization schedule ...
func (rs *RegSyncAPI) Get() {
	rs.getSchedule(common_job.SyncRegistry)
}

// GetLog ...
func (rs *RegSyncAPI) GetLog() {
	id, err := rs.GetInt64FromPath(":id")
	if err != nil {
		rs.SendBadRequestError(errors.New("invalid ID"))
		return
	}
	rs.getLog(id)
}
