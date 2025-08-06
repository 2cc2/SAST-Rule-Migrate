package rules

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type pgORMSQLInjection struct {
	issue.MetaData
	calls      gosec.CallList
	dbTypes    []string
	methodReg  *regexp.Regexp
	importReg  *regexp.Regexp
}

func (p *pgORMSQLInjection) ID() string {
	return p.MetaData.ID
}

func (p *pgORMSQLInjection) isDangerousQuery(n ast.Node, c *gosec.Context) bool {
	if assign, ok := n.(*ast.AssignStmt); ok {
		for _, expr := range assign.Rhs {
			if binExpr, ok := expr.(*ast.BinaryExpr); ok {
				if _, ok := binExpr.X.(*ast.BasicLit); !ok {
					return true
				}
				if _, ok := binExpr.Y.(*ast.BasicLit); !ok {
					return true
				}
			} else if callExpr, ok := expr.(*ast.CallExpr); ok {
				if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					if selExpr.Sel.Name == "Sprintf" {
						return true
					}
				}
			}
		}
	}
	if assign, ok := n.(*ast.AssignStmt); ok && assign.Tok == token.ADD_ASSIGN {
		return true
	}
	return false
}

func (p *pgORMSQLInjection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := p.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if selExpr, ok := node.Fun.(*ast.SelectorExpr); ok {
			if !p.methodReg.MatchString(selExpr.Sel.Name) {
				return nil, nil
			}

			for _, arg := range node.Args {
				if p.isDangerousQuery(arg, c) {
					return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewPgORMSQLInjection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("*pg.DB", "Where")
	calls.Add("*pg.DB", "WhereOr")
	calls.Add("*pg.DB", "Join")
	calls.Add("*pg.DB", "GroupExpr")
	calls.Add("*pg.DB", "OrderExpr")

	return &pgORMSQLInjection{
		calls:     calls,
		dbTypes:   []string{"*pg.DB"},
		methodReg: regexp.MustCompile(`^(Where|WhereOr|Join|GroupExpr|OrderExpr|ColumnExpr)$`),
		importReg: regexp.MustCompile(`.*go-pg`),
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected string concatenation with a non-literal variable in a go-pg ORM SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, do not use strings concatenated with user-controlled input. Instead, use parameterized statements. CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}