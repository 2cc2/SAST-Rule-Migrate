package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type filepathClean struct {
	issue.MetaData
	calls gosec.CallList
}

func (f *filepathClean) ID() string {
	return f.MetaData.ID
}

func (f *filepathClean) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := f.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			if call, ok := arg.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
					if x, ok := selector.X.(*ast.Ident); ok && x.Name == "req" {
						if selector.Sel.Name == "URL" {
							if urlSel, ok := call.Args[0].(*ast.SelectorExpr); ok && urlSel.Sel.Name == "Path" {
								return c.NewIssue(n, f.ID(), f.What, f.Severity, f.Confidence), nil
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewFilePathClean(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("path/filepath", "Clean")
	calls.Add("path", "Clean")
	return &filepathClean{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Medium,
			What:       "`Clean` is not intended to sanitize against path traversal attacks. This function is for finding the shortest path name equivalent to the given input. Using `Clean` to sanitize file reads may expose this application to path traversal attacks. Consider using `filepath.FromSlash(filepath.Clean(\"/\"+strings.Trim(path, \"/\")))` or `filepath-securejoin.SecureJoin` instead.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}