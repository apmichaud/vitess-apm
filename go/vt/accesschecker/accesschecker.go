// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package accesschecker provides access checks. Multiple AccessCheckers
// can be registered and a request for access will succeed only if all
// registered AccessCheckers grant access.
package accesschecker

import (
	"github.com/youtube/vitess/go/vt/context"
	"github.com/youtube/vitess/go/vt/sqlparser"
)

var accesscheckers []AccessChecker

// AccessChecker is the interface for performing access checks for tables
type AccessChecker interface {
	// Load parses and loads access configurations
	// Returns error on invalid configurations
	Load(config []byte) error
	// Allow performs the access checks for a given context on a plan.
	// Returns nil if access is allowed, else the error will state
	// the reason why access is denied.
	Allow(context context.Context, plan *sqlparser.ExecPlan) error
}

// Register registers an AccessChecker
func Register(ac AccessChecker) {
	accesscheckers = append(accesscheckers, ac)
}

// Allow performs the access checks with every registered AccessChecker.
// Access is granted if no AccessCheckers are registered.
func Allow(context context.Context, plan *sqlparser.ExecPlan) error {
	for _, ac := range accesscheckers {
		if err := ac.Allow(context, plan); err != nil {
			return err
		}
	}
	return nil
}
