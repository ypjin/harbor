// Copyright Project Harbor Authors
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

package syncregistry

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	"github.com/goharbor/harbor/src/common"
	commonhttp "github.com/goharbor/harbor/src/common/http"
	"github.com/goharbor/harbor/src/common/secret"
	"github.com/goharbor/harbor/src/jobservice/common/utils"
	"github.com/goharbor/harbor/src/jobservice/config"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/jobservice/logger"
)

// Job is a struct for implementing the interface methods
type Job struct {
	client  *http.Client
	CoreURL string
}

// MaxFails is implementation of same method in Interface.
func (j *Job) MaxFails() uint {
	return 3
}

// ShouldRetry ...
func (j *Job) ShouldRetry() bool {
	return true
}

// Validate is implementation of same method in Interface.
func (j *Job) Validate(params job.Parameters) error {
	return nil
}

// Run the replication logic here.
func (j *Job) Run(ctx job.Context, params job.Parameters) error {

	if err := j.init(ctx, params); err != nil {
		logger.Errorf("SyncRegistry job failed to initialize. %v", err)
		return err
	}

	logger := ctx.GetLogger()

	logger.Info("SyncRegistry job starting")
	defer func() {
		logger.Info("SyncRegistry job exit")
	}()

	address := j.CoreURL + "/api/internal/syncregistry"
	logger.Infof("SyncRegistry job sending request to %s...", address)

	authSecret := config.GetAuthSecret()
	if utils.IsEmptyStr(authSecret) {
		return errors.New("empty auth secret")
	}
	logger.Infof("JOBSERVICE_SECRET: %s", authSecret)

	payload := ""
	if params["payload"] != nil {
		payload = params["payload"].(string)

	}
	req, err := http.NewRequest(http.MethodPost, address, bytes.NewReader([]byte(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s%s", secret.HeaderPrefix, authSecret))

	resp, err := j.client.Do(req)
	if err != nil {
		logger.Errorf("SyncRegistry job failed to send request to harbor-core. %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("SyncRegistry job(target: %s) response code is %d", address, resp.StatusCode)
		logger.Errorf("%v", err)
		return err
	}

	// Successfully exit
	return nil
}

func (j *Job) init(ctx job.Context, params job.Parameters) error {

	errTpl := "failed to get required property: %s"
	if v, ok := ctx.Get(common.CoreURL); ok && len(v.(string)) > 0 {
		j.CoreURL = v.(string)
	} else {
		return fmt.Errorf(errTpl, common.CoreURL)
	}

	// default insecureSkipVerify is false
	insecureSkipVerify := false
	if v, ok := params["skip_cert_verify"]; ok {
		insecureSkipVerify = v.(bool)
	}
	j.client = &http.Client{
		Transport: commonhttp.GetHTTPTransport(insecureSkipVerify),
	}

	return nil
}
