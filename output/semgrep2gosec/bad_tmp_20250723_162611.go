// Converted from Semgrep rule for insecure temp file creation
// Detects file creation in /tmp without using io.CreateTemp
// CWE-377, OWASP A01:2021
package rules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureTempFile struct {
	issue.MetaData
	calls gosec.CallList
}

func (i *insecureTempFile) ID() string {
	return i.MetaData.ID
}

func (i *insecureTempFile) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := i.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			if path, ok := c.Info.ObjectOf(sel.Sel).(*types.Func); ok {
				if basicLit, ok := node.Args[0].(*ast.BasicLit); ok {
					if path.Pkg().Path() == "io/ioutil" && sel.Sel.Name == "WriteFile" && basicLit.Kind == token.STRING && strings.Contains(basicLit.Value, "/tmp/") {
						return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
					}
					if path.Pkg().Path() == "os" && (sel.Sel.Name == "Create" || sel.Sel.Name == "WriteFile") && basicLit.Kind == token.STRING && strings.Contains(basicLit.Value, "/tmp/") {
						return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewInsecureTempFile(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("io/ioutil", "WriteFile")
	calls.Add("os", "Create")
	calls.Add("os", "WriteFile")
	return &insecureTempFile{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "File creation in shared tmp directory without using `io.CreateTemp` (CWE-377, OWASP A01:2021)",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}