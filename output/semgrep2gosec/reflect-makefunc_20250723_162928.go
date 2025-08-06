package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type reflectMakeFunc struct {
	issue.MetaData
	calls gosec.CallList
}

func (r *reflectMakeFunc) ID() string {
	return r.MetaData.ID
}

func (r *reflectMakeFunc) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := r.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
	}
	return nil, nil
}

func NewReflectMakeFunc(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("reflect", "MakeFunc")
	return &reflectMakeFunc{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "'reflect.MakeFunc' detected. This bypasses Go's type system protections. Verify user input cannot affect generated code to prevent serious vulnerabilities.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}