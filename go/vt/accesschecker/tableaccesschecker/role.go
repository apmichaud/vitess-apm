package tableaccesschecker

import (
	"strings"

	"github.com/youtube/vitess/go/vt/sqlparser"
)

// Role defines the role level
type Role int

const (
	// READER can run SELECT statements
	READER Role = iota
	// WRITER can run SELECT, INSERT & UPDATE statements
	WRITER
	// ADMIN can run any statements including DDLs
	ADMIN
	// NumRoles is number of Roles defined
	NumRoles
)

var roleNames = []string{
	"READER",
	"WRITER",
	"ADMIN",
}

// Name returns the name of a role
func (r Role) Name() string {
	if r < READER || r > ADMIN {
		return ""
	}
	return roleNames[r]
}

// RoleByName returns the Role corresponding to a name
func RoleByName(s string) (Role, bool) {
	for i, v := range roleNames {
		if v == strings.ToUpper(s) {
			return Role(i), true
		}
	}
	return NumRoles, false
}

// RoleByPlanType returns the Role required for a PlanType
func RoleByPlanType(planType sqlparser.PlanType) Role {
	return roleByPlanType[planType]
}

var roleByPlanType = map[sqlparser.PlanType]Role{
	sqlparser.PLAN_PASS_SELECT:     READER,
	sqlparser.PLAN_PK_EQUAL:        READER,
	sqlparser.PLAN_PK_IN:           READER,
	sqlparser.PLAN_SELECT_SUBQUERY: READER,
	sqlparser.PLAN_SET:             READER,
	sqlparser.PLAN_PASS_DML:        WRITER,
	sqlparser.PLAN_DML_PK:          WRITER,
	sqlparser.PLAN_DML_SUBQUERY:    WRITER,
	sqlparser.PLAN_INSERT_PK:       WRITER,
	sqlparser.PLAN_INSERT_SUBQUERY: WRITER,
	sqlparser.PLAN_DDL:             ADMIN,
}
