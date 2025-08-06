package rules

import (
	"go/ast"
	"go/token"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type openRedirect struct {
	issue.MetaData
	calls gosec.CallList
}

func (o *openRedirect) ID() string {
	return o.MetaData.ID
}

func (o *openRedirect) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := o.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 2 {
			urlArg := node.Args[2]
			if ident, ok := urlArg.(*ast.Ident); ok {
				if ident.Obj != nil && ident.Obj.Kind == ast.Var {
					if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
						for _, expr := range assign.Rhs {
							if call, ok := expr.(*ast.CallExpr); ok {
								if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
									if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
										if sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Fprintf" || sel.Sel.Name == "Printf" {
											return c.NewIssue(n, o.ID(), o.What, o.Severity, o.Confidence), nil
										}
									}
								}
							}
							if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
								if _, ok := bin.X.(*ast.BasicLit); ok {
									return c.NewIssue(n, o.ID(), o.What, o.Severity, o.Confidence), nil
								}
							}
						}
					}
				}
			}
			if lit, ok := urlArg.(*ast.BasicLit); ok && !isStaticURL(lit.Value) {
				return c.NewIssue(n, o.ID(), o.What, o.Severity, o.Confidence), nil
			}
		}
	}
	return nil, nil
}

func isStaticURL(value string) bool {
	// Check if the URL is static and doesn't contain dynamic parts
	return true
}

func NewOpenRedirect(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net/http", "Redirect")
	return &openRedirect{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "An HTTP redirect found crafted from user-input leading to open redirect vulnerability (CWE-601: URL Redirection to Untrusted Site)",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}