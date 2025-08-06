package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type useTLS struct {
	issue.MetaData
	calls gosec.CallList
}

func (u *useTLS) ID() string {
	return u.MetaData.ID
}

func (u *useTLS) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := u.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
	}
	return nil, nil
}

func NewUseTLS(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net/http", "ListenAndServe")
	return &useTLS{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Found an HTTP server without TLS. Use 'http.ListenAndServeTLS' instead. See https://golang.org/pkg/net/http/#ListenAndServeTLS for more information. CWE-319: Cleartext Transmission of Sensitive Information. OWASP A03:2017 - Sensitive Data Exposure, A02:2021 - Cryptographic Failures",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}