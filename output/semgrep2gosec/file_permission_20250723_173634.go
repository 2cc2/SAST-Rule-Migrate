package rules

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type filePerms struct {
	issue.MetaData
	calls gosec.CallList
}

func (f *filePerms) ID() string {
	return f.MetaData.ID
}

func (f *filePerms) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := f.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if perm, ok := node.Args[1].(*ast.BasicLit); ok {
			if perm.Kind == token.INT {
				value, err := strconv.ParseInt(perm.Value, 0, 64)
				if err != nil {
					return nil, err
				}
				if value > 0600 {
					return c.NewIssue(n, f.ID(), f.What, f.Severity, f.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewFilePerms(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("os", "Chmod")
	calls.Add("os", "Mkdir")
	calls.Add("os", "OpenFile")
	calls.Add("os", "MkdirAll")
	calls.Add("io/ioutil", "WriteFile")
	return &filePerms{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Detected file permissions that are set to more than 0600 (user/owner can read and write). CWE-276: Incorrect Default Permissions",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}