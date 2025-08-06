package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type unescapedJS struct {
	issue.MetaData
	calls gosec.CallList
}

func (u *unescapedJS) ID() string {
	return u.MetaData.ID
}

func (u *unescapedJS) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := u.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) == 0 {
			return nil, nil
		}

		// Check for fmt.Sprintf/Sprintf patterns
		if call, ok := node.Args[0].(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
					return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
				}
			}
		}

		// Check for string concatenation patterns
		if bin, ok := node.Args[0].(*ast.BinaryExpr); ok && bin.Op.String() == "+" {
			return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
		}

		// Check for assigned variables that might contain unescaped data
		if ident, ok := node.Args[0].(*ast.Ident); ok {
			if ident.Obj != nil {
				if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
					for _, rhs := range assign.Rhs {
						if call, ok := rhs.(*ast.CallExpr); ok {
							if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
								if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
									return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
								}
							}
						} else if bin, ok := rhs.(*ast.BinaryExpr); ok && bin.Op.String() == "+" {
							return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewUnescapedJSData(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("html/template", "JS")
	return &unescapedJS{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What: "Found potentially unescaped data passed to template.JS(). " +
				"'template.JS()' does not escape contents. Be absolutely sure there is no " +
				"user-controlled data in this template. CWE-79: Improper Neutralization of " +
				"Input During Web Page Generation ('Cross-site Scripting'). " +
				"OWASP Top 10 2017:A7-XSS, 2021:A3-Injection",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}