// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tableaccesschecker

import (
	"testing"

	"github.com/youtube/vitess/go/vt/context"
	"github.com/youtube/vitess/go/vt/sqlparser"
)

func TestParseInvalidJSON(t *testing.T) {
	checkLoad([]byte(`{1:2}`), false, t)
	checkLoad([]byte(`{"1":"2"}`), false, t)
	checkLoad([]byte(`{"table1":{1:2}}`), false, t)
}

func TestInvalidRoleName(t *testing.T) {
	checkLoad([]byte(`{"table1":{"SOMEROLE":"user1"}}`), false, t)
}

func TestInvalidRegex(t *testing.T) {
	checkLoad([]byte(`{"table(1":{"READER":"user1"}}`), false, t)
}

func TestValidConfigs(t *testing.T) {
	checkLoad([]byte(`{"table1":{"READER":"user1"}}`), true, t)
	checkLoad([]byte(`{"table1":{"READER":"user1,user2", "WRITER":"user3"}}`), true, t)
	checkLoad([]byte(`{"table[0-9]+":{"Reader":"user1,user2", "WRITER":"user3"}}`), true, t)
	checkLoad([]byte(`{"table[0-9]+":{"Reader":"user1,*", "WRITER":"user3"}}`), true, t)
	checkLoad([]byte(`{
		"table[0-9]+":{"Reader":"user1,*", "WRITER":"user3"},
		"tbl[0-9]+":{"Reader":"user1,*", "WRITER":"user3", "ADMIN":"user4"}
	}`), true, t)

}

func TestDenyReaderInsert(t *testing.T) {
	ctx := &context.DummyContext{}
	configData := []byte(`{"table[0-9]+":{"Reader":"` + ctx.GetUsername() + `", "WRITER":"user3"}}`)
	plan := &sqlparser.ExecPlan{PlanId: sqlparser.PLAN_INSERT_PK, TableName: "table1"}
	checkAllow(configData, plan, t, false)
}

func TestAllowReaderSelect(t *testing.T) {
	ctx := &context.DummyContext{}
	configData := []byte(`{"table[0-9]+":{"Reader":"` + ctx.GetUsername() + `", "WRITER":"user3"}}`)
	plan := &sqlparser.ExecPlan{PlanId: sqlparser.PLAN_PK_IN, TableName: "table1"}
	checkAllow(configData, plan, t, true)
}

func TestDenyReaderDDL(t *testing.T) {
	ctx := &context.DummyContext{}
	configData := []byte(`{"table[0-9]+":{"Reader":"` + ctx.GetUsername() + `", "WRITER":"user3"}}`)
	plan := &sqlparser.ExecPlan{PlanId: sqlparser.PLAN_DDL, TableName: "table1"}
	checkAllow(configData, plan, t, false)
}

func TestAllowUnmatchedTable(t *testing.T) {
	ctx := &context.DummyContext{}
	configData := []byte(`{"table[0-9]+":{"Reader":"` + ctx.GetUsername() + `", "WRITER":"user3"}}`)
	plan := &sqlparser.ExecPlan{PlanId: sqlparser.PLAN_DDL, TableName: "UNMATCHED_TABLE"}
	checkAllow(configData, plan, t, true)
}

func TestAllUserReadAcess(t *testing.T) {
	configData := []byte(`{"table[0-9]+":{"Reader":"*", "WRITER":"user3"}}`)
	plan := &sqlparser.ExecPlan{PlanId: sqlparser.PLAN_PASS_SELECT, TableName: "table1"}
	checkAllow(configData, plan, t, true)
}

func TestAllUserWriteAccess(t *testing.T) {
	ctx := &context.DummyContext{}
	configData := []byte(`{"table[0-9]+":{"Reader":"` + ctx.GetUsername() + `", "WRITER":"*"}}`)
	plan := &sqlparser.ExecPlan{PlanId: sqlparser.PLAN_DML_SUBQUERY, TableName: "table1"}
	checkAllow(configData, plan, t, true)
}

func checkLoad(configData []byte, valid bool, t *testing.T) {
	ac := &tableAccessChecker{acl: make(map[string]map[string]Role)}
	err := ac.Load(configData)
	if !valid && err == nil {
		t.Errorf("expecting parse error none returned")
	}

	if valid && err != nil {
		t.Errorf("unexpected load error: %v", err)
	}
}

func checkAllow(configData []byte, plan *sqlparser.ExecPlan, t *testing.T, allow bool) {
	ac := &tableAccessChecker{acl: make(map[string]map[string]Role)}
	err := ac.Load(configData)
	if err != nil {
		t.Errorf("load error: %v", err)
	}
	err = ac.Allow(&context.DummyContext{}, plan)
	if allow && err != nil {
		t.Errorf("unexpected error %v", err)
	}
	if !allow && err == nil {
		t.Errorf("expected error to be non-nil")
	}
}
