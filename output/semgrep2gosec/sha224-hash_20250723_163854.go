package rules

import (
	"go/ast"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type weakHash224 struct {
	issue.MetaData
	calls gosec.CallList
}

func (w *weakHash224) ID() string {
	return w.MetaData.ID
}

func (w *weakHash224) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := w.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
	}
	return nil, nil
}

func NewWeakHash224(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("crypto/sha256", "New224")
	calls.Add("crypto/sha256", "Sum224")
	calls.Add("golang.org/x/crypto/sha3", "New224")
	calls.Add("golang.org/x/crypto/sha3", "Sum224")
	return &weakHash224{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and security.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}