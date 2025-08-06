package rules

import (
	"go/ast"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type bindAllInterfaces struct {
	issue.MetaData
	calls gosec.CallList
}

func (b *bindAllInterfaces) ID() string {
	return b.MetaData.ID
}

func (b *bindAllInterfaces) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := b.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 1 {
			if arg, ok := node.Args[1].(*ast.BasicLit); ok {
				address := strings.Trim(arg.Value, "\"")
				if strings.HasPrefix(address, "0.0.0.0:") || strings.HasPrefix(address, ":") {
					return c.NewIssue(n, b.ID(), b.What, b.Severity, b.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewBindAllInterfaces creates a rule that detects network listeners binding to all interfaces
func NewBindAllInterfaces(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net", "Listen")
	calls.Add("crypto/tls", "Listen")
	return &bindAllInterfaces{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Detected a network listener listening on 0.0.0.0 or an empty string. This could unexpectedly expose the server publicly as it binds to all available interfaces. CWE-200, OWASP A01:2021",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}