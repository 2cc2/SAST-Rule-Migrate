package rules

import (
	"go/ast"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sqlInjection struct {
	issue.MetaData
	calls gosec.CallList
}

func (s *sqlInjection) ID() string {
	return s.MetaData.ID
}

func (s *sqlInjection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := s.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			if ident, ok := arg.(*ast.Ident); ok {
				if ident.Obj != nil {
					decl := ident.Obj.Decl
					if assign, ok := decl.(*ast.AssignStmt); ok {
						for _, expr := range assign.Rhs {
							if call, ok := expr.(*ast.CallExpr); ok {
								if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
									if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "lambda" && sel.Sel.Name == "Start" {
										return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewSQLInjection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("database/sql", "Exec")
	calls.Add("database/sql", "ExecContext")
	calls.Add("database/sql", "Query")
	calls.Add("database/sql", "QueryContext")
	calls.Add("database/sql", "QueryRow")
	calls.Add("database/sql", "QueryRowContext")
	return &sqlInjection{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Detected SQL statement that could lead to SQL injection if the variable is user-controlled and not properly sanitized. Use parameterized queries or prepared statements instead (via 'Prepare' or 'PrepareContext'). References: https://pkg.go.dev/database/sql#DB.Query",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}