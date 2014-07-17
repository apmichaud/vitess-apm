package tableaccesschecker

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"

	"github.com/youtube/vitess/go/vt/accesschecker"
	"github.com/youtube/vitess/go/vt/context"
	"github.com/youtube/vitess/go/vt/sqlparser"
)

var configFile string

func init() {
	flag.StringVar(&configFile, "table-accesschecker-config-file", "", "path to per table access checker's configuration file")
}

func Register() error {
	ac, err := New(configFile)
	if err != nil {
		return err
	}
	accesschecker.Register(ac)
	return nil
}

// tableAccessChecker is a per table AccessChecker
type tableAccessChecker struct {
	mu  sync.RWMutex
	acl map[string]map[string]Role
}

// NewTableAccessChecker creates a tableAccessChecker based on a JSON config file
func New(configFile string) (accesschecker.AccessChecker, error) {
	ac := &tableAccessChecker{acl: make(map[string]map[string]Role)}
	config, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	err = ac.Load(config)
	if err != nil {
		return nil, err
	}
	return ac, nil
}

// Load loads configurations from a JSON byte array
//
// Sample configuration
// []byte (`{
//	<tableRegexPattern1>: {"READER": "*", "WRITER": "<user2>,<user4>...","ADMIN": "<user5>"},
//	<tableRegexPattern2>: {"ADMIN": "<user5>"}
//}`)
func (ac *tableAccessChecker) Load(config []byte) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	var contents map[string]map[string]string
	err := json.Unmarshal(config, &contents)
	if err != nil {
		return err
	}
	for tablePattern, accessMap := range contents {
		if _, err = regexp.Compile(tablePattern); err != nil {
			return fmt.Errorf("regexp compile error %v: %v", tablePattern, err)
		}
		if _, ok := ac.acl[tablePattern]; !ok {
			ac.acl[tablePattern] = make(map[string]Role)
		}
		for role, usersStr := range accessMap {
			r, ok := RoleByName(role)
			if !ok {
				return fmt.Errorf("parse error, invalid role %v", role)
			}
			for _, u := range strings.Split(usersStr, ",") {
				ac.acl[tablePattern][u] = r
			}
		}
	}
	return nil
}

// Allow implements AccessChecker.Allow().
// For an unmatched table pattern, all access is allowed by default.
// If a match is found, it first checks for default access followed
// by user specific access as per the context.
func (ac *tableAccessChecker) Allow(context context.Context, plan *sqlparser.ExecPlan) error {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	minRole := RoleByPlanType(plan.PlanId)
	for tablePattern, accessMap := range ac.acl {
		// TODO(anandhenry): Check all tables once parser can expose multiple tables
		if matched, _ := regexp.MatchString(tablePattern, plan.TableName); matched {
			// Check default access
			if defaultRole, ok := accessMap["*"]; ok && defaultRole >= minRole {
				return nil
			}
			// Check user specific access
			if myRole, ok := accessMap[context.GetUsername()]; ok && myRole >= minRole {
				return nil
			}
			return fmt.Errorf("user %v has no %v access on table %v", context.GetUsername(), minRole.Name(), plan.TableName)
		}
	}
	// No matching patterns for table, allow all access
	return nil
}
