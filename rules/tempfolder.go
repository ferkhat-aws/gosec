// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not
// use this file except in compliance with the License. A copy of the
// License is located at
//
// http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package rules

import (
	"github.com/securego/gosec/v2"
	"go/ast"
)


type badTempFolder struct {
	gosec.MetaData
	funcNames   []string
	packagePaths []string
}

func (w *badTempFolder) ID() string {
	return w.MetaData.ID
}

func (w *badTempFolder) Match(n ast.Node, c *gosec.Context) (*gosec.Issue, error) {
	for _, funcName := range w.funcNames {
		for _, packagePath := range w.packagePaths {
			if _, matched := gosec.MatchCallByPackage(n, c, packagePath, funcName); matched {
				return gosec.NewIssue(c, n, w.ID(), w.What, w.Severity, w.Confidence), nil
			}
		}
	}

	return nil, nil
}

// NewBadTempFolder detects if there is a usage of os.TempDir
func NewBadTempFolder(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	return &badTempFolder{
		funcNames: []string{"TempDir"},
		packagePaths: []string{"os", "ioutil"},
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.High,
			Confidence: gosec.Medium,
			What:       "Use of os.TempDir is not recommended",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}

