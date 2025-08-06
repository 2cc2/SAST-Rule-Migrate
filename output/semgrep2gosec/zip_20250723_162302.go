package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type zipPathTraversal struct {
	issue.MetaData
	calls    gosec.CallList
	argTypes []string
}

func (z *zipPathTraversal) ID() string {
	return z.MetaData.ID
}

func (z *zipPathTraversal) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := z.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			var argType types.Type
			if selector, ok := arg.(*ast.SelectorExpr); ok {
				argType = c.Info.TypeOf(selector.X)
			} else if ident, ok := arg.(*ast.Ident); ok {
				if ident.Obj != nil && ident.Obj.Kind == ast.Var {
					decl := ident.Obj.Decl
					if assign, ok := decl.(*ast.AssignStmt); ok {
						if selector, ok := assign.Rhs[0].(*ast.SelectorExpr); ok {
							argType = c.Info.TypeOf(selector.X)
						}
					}
				}
			}

			if argType != nil {
				for _, t := range z.argTypes {
					if argType.String() == t {
						return c.NewIssue(n, z.ID(), z.What, z.Severity, z.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewZipPathTraversal(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("path/filepath", "Join")
	calls.Add("path", "Join")
	return &zipPathTraversal{
		calls:    calls,
		argTypes: []string{"*archive/zip.File"},
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "File traversal when extracting zip archive (CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}