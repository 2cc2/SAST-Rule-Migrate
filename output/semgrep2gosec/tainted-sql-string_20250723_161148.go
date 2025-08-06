package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type taintedSQL struct {
	issue.MetaData
	sqlCalls gosec.CallList
	fmtCalls gosec.CallList
}

func (t *taintedSQL) ID() string {
	return t.MetaData.ID
}

func (t *taintedSQL) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for direct SQL string concatenation
	if node := t.sqlCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
	}

	// Check for SQL in fmt functions
	if node := t.fmtCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
	}

	return nil, nil
}

func NewTaintedSQL(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	sqlCalls := gosec.NewCallList()
	sqlCalls.Add("", "+") // String concatenation as SQL injection vector

	fmtCalls := gosec.NewCallList()
	fmtCalls.Add("fmt", "Sprintf")
	fmtCalls.Add("fmt", "Printf")
	fmtCalls.Add("fmt", "Fprintf")

	return &taintedSQL{
		sqlCalls: sqlCalls,
		fmtCalls: fmtCalls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Medium,
			What:       "Detected user input used to manually construct a SQL string. This could result in SQL injection. Use parameterized queries or ORM instead. References: https://owasp.org/www-community/attacks/SQL_Injection",
		},
	}, []ast.Node{(*ast.BinaryExpr)(nil), (*ast.CallExpr)(nil)}
}