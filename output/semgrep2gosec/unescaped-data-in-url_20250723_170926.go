package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type unescapedURL struct {
	issue.MetaData
	calls gosec.CallList
}

func (u *unescapedURL) ID() string {
	return u.MetaData.ID
}

func (u *unescapedURL) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := u.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			// Check for string concatenation
			if binExpr, ok := arg.(*ast.BinaryExpr); ok && binExpr.Op.String() == "+" {
				return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
			}

			// Check for fmt.Sprintf usage
			if callExpr, ok := arg.(*ast.CallExpr); ok {
				if selector, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "fmt" {
						return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
					}
				}
			}

			// Check for variables that might be constructed from unsafe sources
			if ident, ok := arg.(*ast.Ident); ok {
				if ident.Obj != nil {
					if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
						for _, rhs := range assign.Rhs {
							if _, ok := rhs.(*ast.BinaryExpr); ok {
								return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
							}
							if callExpr, ok := rhs.(*ast.CallExpr); ok {
								if selector, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
									if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "fmt" {
										return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewUnescapedURL(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("html/template", "URL")
	return &unescapedURL{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Found unescaped data passed to template.URL(). This could result in XSS vulnerabilities. Sanitize all user-controlled input or use template.HTMLEscapeString() first. CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}