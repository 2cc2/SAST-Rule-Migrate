package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type templateHTML struct {
	issue.MetaData
	calls gosec.CallList
}

func (t *templateHTML) ID() string {
	return t.MetaData.ID
}

func (t *templateHTML) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := t.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		// Check for simple string concatenation
		if len(node.Args) > 0 {
			if binExpr, ok := node.Args[0].(*ast.BinaryExpr); ok && binExpr.Op.String() == "+" {
				return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
			}
		}

		// Check for fmt package function calls
		if selector, ok := node.Args[0].(*ast.CallExpr); ok {
			if sel, ok := selector.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
					return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
				}
			}
		}

		// Check for variables that might contain formatted strings
		if ident, ok := node.Args[0].(*ast.Ident); ok {
			if ident.Obj != nil {
				if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
					for _, rhs := range assign.Rhs {
						if binaryExpr, ok := rhs.(*ast.BinaryExpr); ok && binaryExpr.Op.String() == "+" {
							return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
						}
						if callExpr, ok := rhs.(*ast.CallExpr); ok {
							if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
								if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
									return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
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

func NewFormattedTemplateString(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("html/template", "HTML")
	return &templateHTML{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Found a formatted template string passed to 'template.HTML()'. 'template.HTML()' does not escape contents. Be absolutely sure there is no user-controlled data in this template. If user data can reach this template, you may have a XSS vulnerability. CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}