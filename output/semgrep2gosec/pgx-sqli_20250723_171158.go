package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type pgxSQLInjection struct {
	issue.MetaData
	dbCalls   gosec.CallList
	connCalls gosec.CallList
}

func (p *pgxSQLInjection) ID() string {
	return p.MetaData.ID
}

func (p *pgxSQLInjection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for SQL method calls
	if node := p.dbCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		// Check query construction
		for _, arg := range node.Args {
			switch expr := arg.(type) {
			case *ast.BinaryExpr:
				// Detect string concatenation
				return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
			case *ast.CallExpr:
				if sel, ok := expr.Fun.(*ast.SelectorExpr); ok {
					if sel.Sel.Name == "Sprintf" {
						// Detect fmt.Sprintf usage
						return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
					}
				}
			}
		}
	}

	// Check for db connection initialization
	if _, ok := n.(*ast.AssignStmt); ok {
		if node := p.connCalls.ContainsPkgCallExpr(n, c, false); node != nil {
			return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
		}
	}

	return nil, nil
}

func NewPgxSQLInjection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	dbMethods := gosec.NewCallList()
	dbMethods.Add("github.com/jackc/pgx", "Exec")
	dbMethods.Add("github.com/jackc/pgx", "ExecEx")
	dbMethods.Add("github.com/jackc/pgx", "Query")
	dbMethods.Add("github.com/jackc/pgx", "QueryEx")
	dbMethods.Add("github.com/jackc/pgx", "QueryRow")
	dbMethods.Add("github.com/jackc/pgx", "QueryRowEx")

	connMethods := gosec.NewCallList()
	connMethods.Add("github.com/jackc/pgx", "Connect")
	connMethods.Add("github.com/jackc/pgx", "NewConnPool")
	connMethods.Add("github.com/jackc/pgx", "ConnectConfig")

	return &pgxSQLInjection{
		dbCalls:   dbMethods,
		connCalls: connMethods,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected string concatenation with non-literal variable in pgx SQL statement. This could lead to SQL injection. Use parameterized queries instead. References: https://github.com/jackc/pgx, https://pkg.go.dev/github.com/jackc/pgx/v4#hdr-Connection_Pool",
		},
	}, []ast.Node{(*ast.CallExpr)(nil), (*ast.AssignStmt)(nil)}
}