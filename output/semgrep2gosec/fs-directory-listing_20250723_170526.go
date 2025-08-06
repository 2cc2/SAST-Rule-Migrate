package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type fileServerUsage struct {
	issue.MetaData
	calls gosec.CallList
}

func (f *fileServerUsage) ID() string {
	return f.MetaData.ID
}

func (f *fileServerUsage) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := f.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, f.ID(), f.What, f.Severity, f.Confidence), nil
	}
	return nil, nil
}

func NewFileServerUsage(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net/http", "ListenAndServe")
	calls.Add("net/http", "ListenAndServeTLS")
	calls.Add("net/http", "Handle")
	calls.Add("net/http", "HandleFunc")
	calls.Add("net/http", "FileServer")

	return &fileServerUsage{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Detected usage of 'http.FileServer' as handler: this allows directory listing and an attacker could navigate through directories looking for sensitive files. Be sure to disable directory listing or restrict access to specific directories/files. CWE-548: Exposure of Information Through Directory Listing",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}