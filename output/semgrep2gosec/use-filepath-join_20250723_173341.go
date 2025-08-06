package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type filepathJoin struct {
	issue.MetaData
	calls gosec.CallList
}

func (f *filepathJoin) ID() string {
	return f.MetaData.ID
}

func (f *filepathJoin) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := f.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		pkg, funcName := "", ""
		switch x := node.Fun.(type) {
		case *ast.SelectorExpr:
			if ident, ok := x.X.(*ast.Ident); ok {
				pkg = ident.Name
			}
			funcName = x.Sel.Name
		}

		if pkg == "path" && funcName == "Join" {
			return c.NewIssue(n, f.ID(), f.What, f.Severity, f.Confidence), nil
		}
	}
	return nil, nil
}

// NewUseFilepathJoin creates a rule that detects path.Join usage
func NewUseFilepathJoin(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("path", "Join")
	calls.Add("path/filepath", "Join")
	return &filepathJoin{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "`path.Join(...)` always joins using a forward slash. This may cause issues on Windows or other systems using a different delimiter. Use `filepath.Join(...)` instead which uses OS-specific path separators.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}