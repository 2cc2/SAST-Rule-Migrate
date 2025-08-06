package rules

import (
	"go/ast"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type taintedURLHost struct {
	issue.MetaData
	clientCalls gosec.CallList
	httpCalls   gosec.CallList
}

func (t *taintedURLHost) ID() string {
	return t.MetaData.ID
}

func (t *taintedURLHost) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for http.Client method calls
	if node := t.clientCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			if urlArg, ok := node.Args[0].(*ast.BasicLit); ok && isUserControlledURL(urlArg, c) {
				return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
			}
		}
	}

	// Check for direct http package method calls
	if node := t.httpCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			if urlArg, ok := node.Args[0].(*ast.BasicLit); ok && isUserControlledURL(urlArg, c) {
				return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
			}
		}
	}

	// Check for http.NewRequest calls
	if callExpr, ok := n.(*ast.CallExpr); ok {
		if selector, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			if x, ok := selector.X.(*ast.Ident); ok && x.Name == "http" && selector.Sel.Name == "NewRequest" {
				if len(callExpr.Args) > 1 {
					if urlArg, ok := callExpr.Args[1].(*ast.BasicLit); ok && isUserControlledURL(urlArg, c) {
						return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
					}
				}
			}
		}
	}

	return nil, nil
}

func isUserControlledURL(expr ast.Expr, c *gosec.Context) bool {
	// Implement logic to check if the URL contains user-controlled input
	// This would involve checking if the URL contains variables derived from http.Request fields
	return true
}

func NewTaintedURLHost(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	clientCalls := gosec.NewCallList()
	clientCalls.Add("net/http", "Get")
	clientCalls.Add("net/http", "Head")
	clientCalls.Add("net/http", "Post")
	clientCalls.Add("net/http", "PostForm")

	httpCalls := gosec.NewCallList()
	httpCalls.Add("net/http", "Do")
	httpCalls.Add("net/http", "Get")
	httpCalls.Add("net/http", "Head")
	httpCalls.Add("net/http", "Post")
	httpCalls.Add("net/http", "PostForm")

	return &taintedURLHost{
		clientCalls: clientCalls,
		httpCalls:   httpCalls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "A request was found to be crafted from user-input. This can lead to Server-Side Request Forgery (SSRF) vulnerabilities. CWE-918, OWASP A10:2021",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}