package rules

import (
	"go/ast"
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type pgSQLInjection struct {
	issue.MetaData
	dbCalls    gosec.CallList
	queryFuncs *regexp.Regexp
}

func (p *pgSQLInjection) ID() string {
	return p.MetaData.ID
}

func (p *pgSQLInjection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := p.dbCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			// Check for direct string concatenation
			if binaryExpr, ok := arg.(*ast.BinaryExpr); ok && (binaryExpr.Op.String() == "+") {
				return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
			}

			// Check for fmt.Sprintf usage
			if callExpr, ok := arg.(*ast.CallExpr); ok {
				if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					if selExpr.Sel.Name == "Sprintf" {
						return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
					}
				}
			}

			// Check for += concatenation pattern
			if ident, ok := arg.(*ast.Ident); ok {
				if ident.Obj != nil && ident.Obj.Kind == ast.Var {
					if _, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
						for _, stmt := range c.PkgFiles {
							ast.Inspect(stmt, func(n ast.Node) bool {
								if assignStmt, ok := n.(*ast.AssignStmt); ok {
									for i, rhs := range assignStmt.Rhs {
										if lhs, ok := assignStmt.Lhs[i].(*ast.Ident); ok && lhs.Name == ident.Name {
											if binaryExpr, ok := rhs.(*ast.BinaryExpr); ok && (binaryExpr.Op.String() == "+") {
												return true
											}
										}
									}
								}
								return true
							})
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewPgSQLInjection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	dbCalls := gosec.NewCallList()
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "Exec")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "ExecContext")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "ExecOne")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "ExecOneContext")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "Query")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "QueryOne")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "QueryContext")
	dbCalls.Add("*github.com/go-pg/pg/v10.DB", "QueryOneContext")

	return &pgSQLInjection{
		dbCalls: dbCalls,
		queryFuncs: regexp.MustCompile(
			`^(Exec|ExecContext|ExecOne|ExecOneContext|Query|QueryOne|QueryContext|QueryOneContext)$`,
		),
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Potential SQL injection in go-pg due to string concatenation. Use parameterized queries instead. CWE-89, OWASP A1/A3 vulnerability",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}