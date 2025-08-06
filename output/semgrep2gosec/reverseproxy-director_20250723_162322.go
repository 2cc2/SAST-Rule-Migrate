package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type reverseProxyDirector struct {
	issue.MetaData
	proxyType string
}

func (r *reverseProxyDirector) ID() string {
	return r.MetaData.ID
}

// Match inspects AST nodes to determine if ReverseProxy uses Director field
func (r *reverseProxyDirector) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if assign, ok := n.(*ast.AssignStmt); ok {
		for _, expr := range assign.Lhs {
			if selector, ok := expr.(*ast.SelectorExpr); ok {
				if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == r.proxyType {
					if selector.Sel.Name == "Director" {
						return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
					}
				}
			}
		}
	} else if kv, ok := n.(*ast.KeyValueExpr); ok {
		if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "Director" {
			return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

// NewReverseProxyDirector creates a new rule which detects usage of ReverseProxy.Director
func NewReverseProxyDirector(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &reverseProxyDirector{
		proxyType: "httputil.ReverseProxy",
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "ReverseProxy can remove headers added by Director. Consider using ReverseProxy.Rewrite instead of ReverseProxy.Director. CWE-115: Misinterpretation of Input",
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.KeyValueExpr)(nil)}
}