package ars

import (
	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/dao/project"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils/log"
)

// compare 2 set of organizations
func compareOrgMaps(cachedOrgs, freshOrgs map[string]Org) (bool, []Org, []Org, []Org) {

	// Orgs the user has been added as a member
	newOrgs := []Org{}
	// Orgs the user is no longer a member of
	removedOrgs := []Org{}
	// Orgs the user's role has changed
	updatedOrgs := []Org{}

	changed := false

	for orgID, org := range cachedOrgs {
		if fresh, ok := freshOrgs[orgID]; ok {
			if !compareOrgs(org, fresh) {
				updatedOrgs = append(updatedOrgs, fresh)
			}
		} else {
			removedOrgs = append(removedOrgs, org)
		}
	}

	for orgID, org := range freshOrgs {
		if _, ok := cachedOrgs[orgID]; !ok {
			newOrgs = append(newOrgs, org)
		}
	}

	if len(newOrgs) > 0 || len(removedOrgs) > 0 || len(updatedOrgs) > 0 {
		changed = true
	}

	return changed, newOrgs, removedOrgs, updatedOrgs
}

// compare 2 Org
func compareOrgs(old, new Org) bool {
	same := true
	if old.ARSAdmin != new.ARSAdmin {
		same = false
	}
	return same
}

func mapOrgsToProjectsAndMembers(user *models.User, newOrgs, removedOrgs, updatedOrgs []Org) error {

	log.Debug("mapOrgsToProjectsAndMembers")

	err := createProjectsAndMembers(user, newOrgs)
	if err != nil {
		return err
	}

	err = removeMembersAndProjects(user, removedOrgs)
	if err != nil {
		return err
	}

	err = updateProjectMemberRole(user, updatedOrgs)
	if err != nil {
		return err
	}

	return nil
}

// create projects for the new organizations and add the user as member to them
// need to check if a project exists for an org
func createProjectsAndMembers(user *models.User, newOrgs []Org) error {

	log.Debugf("createProjectsAndMembers for user %s: %+v", user.Email, newOrgs)

	for _, org := range newOrgs {
		log.Debugf("process org %s(%s), node_acs_admin: %v", org.ID, org.Name, org.ARSAdmin)

		// org ID as project name
		var projectID int64
		existingProject, err := dao.GetProjectByName(org.ID)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}

		if existingProject == nil {
			log.Debugf("project %s does not exist", org.ID)
			newProject := models.Project{
				OwnerID: 1,
				Name:    org.ID,
			}
			projectID, err = dao.AddProject(newProject)
			if err != nil {
				log.Errorf("%v", err)
				return err
			}
		} else {
			log.Debugf("project %s exists", org.ID)
			projectID = existingProject.ProjectID
		}

		newMember := models.Member{
			ProjectID:  projectID,
			EntityID:   user.UserID,
			EntityType: common.UserMember,
		}

		if org.ARSAdmin {
			newMember.Role = models.DEVELOPER
		} else {
			newMember.Role = models.GUEST
		}

		log.Debugf("add user as member: %+v", newMember)

		// TODO handling error if the member exists already
		// should be ok, AddProjectMember does deletion first
		_, err = project.AddProjectMember(newMember)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}

	}
	return nil
}

func removeMembersAndProjects(user *models.User, removedOrgs []Org) error {

	log.Debugf("removeMembersAndProjects for user %s: %+v", user.Email, removedOrgs)

	if len(removedOrgs) == 0 {
		return nil
	}

	// get project IDs by names
	projectIDs := []int64{}

	for _, org := range removedOrgs {
		project, err := dao.GetProjectByName(org.ID)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}
		projectIDs = append(projectIDs, project.ProjectID)
	}

	log.Debugf("delete all members of projects %v", projectIDs)
	// delete member by project IDs and member ID
	err := project.DeleteProjectMemberByEntityIDAndProjectIDs(user.UserID, projectIDs)
	if err != nil {
		log.Errorf("%v", err)
		return err
	}

	// TODO How about the images of these projects? May not be a good idea to remove the projects here.
	// Just leave them as they are. Probably needs a kind of GC.
	// remove project having no member GetTotalOfProjectMembers
	for _, projectID := range projectIDs {
		cnt, err := project.GetTotalOfProjectMembers(projectID)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}
		if cnt == 1 { // will not be zero since we set admin as the ProjectAdmin of the projects
			log.Warningf("project %v has no member, about to delete it", projectID)
			err = dao.DeleteProject(projectID)
			if err != nil {
				log.Errorf("%v", err)
				// This error could be ignored.
				log.Warningf("error deleting project %v which don't have any members.", projectID)
			}
		}
	}

	return nil
}

func updateProjectMemberRole(user *models.User, updatedOrgs []Org) error {

	log.Debugf("updateProjectMemberRole for user %s: %+v", user.Email, updatedOrgs)

	for _, org := range updatedOrgs {

		var newRole int
		if org.ARSAdmin {
			newRole = models.DEVELOPER
		} else {
			newRole = models.GUEST
		}

		// org ID as project name
		proj, err := dao.GetProjectByName(org.ID)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}

		members, err := project.GetProjectMemberByProjectIDAndEntityID(proj.ProjectID, user.UserID)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}

		if len(members) == 0 {
			log.Warningf("project member not found by project ID %v for user %v", proj.ProjectID, user.UserID)
			// TODO create the member
			newMember := models.Member{
				ProjectID:  proj.ProjectID,
				EntityID:   user.UserID,
				EntityType: common.UserMember,
				Role:       newRole,
			}
			log.Debugf("add missing member: %+v", newMember)
			_, err = project.AddProjectMember(newMember)
			if err != nil {
				log.Errorf("%v", err)
				return err
			}
			continue
		}

		err = project.UpdateProjectMemberRole(members[0].ID, newRole)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}
	}

	return nil
}
