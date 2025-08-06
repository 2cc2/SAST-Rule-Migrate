package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type unsafeTemplate struct {
	issue.MetaData
	calls gosec.CallList
}

func (u *unsafeTemplate) ID() string {
	return u.MetaData.ID
}

func (u *unsafeTemplate) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := u.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			if _, ok := arg.(*ast.BasicLit); !ok {
				return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewUnsafeTemplate(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("html/template", "HTML")
	calls.Add("html/template", "CSS")
	calls.Add("html/template", "HTMLAttr")
	calls.Add("html/template", "JS")
	calls.Add("html/template", "JSStr")
	calls.Add("html/template", "Srcset")
	calls.Add("html/template", "URL")
	return &unsafeTemplate{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What: "Unsafe usage of template functions that don't escape content (potential XSS). " +
				"Functions like template.HTML() should only be used with constant strings. " +
				"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}