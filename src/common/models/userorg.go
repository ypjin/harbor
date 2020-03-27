package models

import "time"

// UserOrgTable is the name of table in DB that holds the UserOrg objects
const UserOrgTable = "user_org"

// UserOrg holds the organizations of a user.
type UserOrg struct {
	UserID       int       `orm:"pk;auto;column(user_id)" json:"user_id"`
	Orgs         string    `orm:"column(orgs);type(jsonb)" json:"-"`
	CreationTime time.Time `orm:"column(creation_time);auto_now_add" json:"creation_time"`
	UpdateTime   time.Time `orm:"column(update_time);auto_now" json:"update_time"`
}

// TableName ...
func (u *UserOrg) TableName() string {
	return UserOrgTable
}
