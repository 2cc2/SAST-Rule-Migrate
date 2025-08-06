package rules

import (
	"go/ast"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureSSH struct {
	issue.MetaData
	calls gosec.CallList
}

func (i *insecureSSH) ID() string {
	return i.MetaData.ID
}

func (i *insecureSSH) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := i.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
	}
	return nil, nil
}

func NewInsecureSSH(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("golang.org/x/crypto/ssh", "InsecureIgnoreHostKey")
	return &insecureSSH{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Disabled host key verification detected. This allows man-in-the-middle attacks. Use the 'golang.org/x/crypto/ssh/knownhosts' package to do host key verification. See references for remediation.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}