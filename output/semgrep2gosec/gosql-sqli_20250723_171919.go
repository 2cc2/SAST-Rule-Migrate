package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sqlInjection struct {
	issue.MetaData
	dbMethods gosec.CallList
}

func (s *sqlInjection) ID() string {
	return s.MetaData.ID
}

func (s *sqlInjection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := s.dbMethods.ContainsPkgCallExpr(n, c, false); node != nil {
		// Check for string concatenation or sprintf in query argument
		for _, arg := range node.Args {
			switch expr := arg.(type) {
			case *ast.BinaryExpr:
				return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
			case *ast.CallExpr:
				if selector, ok := expr.Fun.(*ast.SelectorExpr); ok {
					if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "fmt" && selector.Sel.Name == "Sprintf" {
						return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

// NewSQLInjection creates a rule to detect potential SQL injection vulnerabilities
func NewSQLInjection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	dbMethods := gosec.NewCallList()
	dbMethods.Add("database/sql", "Exec")
	dbMethods.Add("database/sql", "ExecContext")
	dbMethods.Add("database/sql", "Query")
	dbMethods.Add("database/sql", "QueryContext")
	dbMethods.Add("database/sql", "QueryRow")
	dbMethods.Add("database/sql", "QueryRowContext")

	return &sqlInjection{
		dbMethods: dbMethods,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected string concatenation with a non-literal variable in SQL statement. This could lead to SQL injection. Use parameterized queries or prepared statements instead. CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}