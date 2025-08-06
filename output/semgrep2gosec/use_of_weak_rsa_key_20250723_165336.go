package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type weakRSAKey struct {
	issue.MetaData
	calls gosec.CallList
}

func (w *weakRSAKey) ID() string {
	return w.MetaData.ID
}

func (w *weakRSAKey) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := w.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			if bits, ok := node.Args[0].(*ast.BasicLit); ok {
				if bits.Value < "2048" {
					return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewWeakRSAKey(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("crypto/rsa", "GenerateKey")
	calls.Add("crypto/rsa", "GenerateMultiPrimeKey")
	return &weakRSAKey{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "RSA keys should be at least 2048 bits (CWE-326, OWASP A03:2017, A02:2021)",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}