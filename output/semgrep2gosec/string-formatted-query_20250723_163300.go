package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type stringFormattedQuery struct {
	issue.MetaData
	dbCalls  gosec.CallList
	queryCalls gosec.CallList
	fmtCalls gosec.CallList
}

func (s *stringFormattedQuery) ID() string {
	return s.MetaData.ID
}

func (s *stringFormattedQuery) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for database method calls
	if dbNode := s.dbCalls.ContainsPkgCallExpr(n, c, false); dbNode != nil {
		// Check for concatenated or formatted query arguments
		for _, arg := range dbNode.Args {
			switch arg := arg.(type) {
			case *ast.BinaryExpr:
				if arg.Op.String() == "+" {
					return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
				}
			case *ast.CallExpr:
				if fmtNode := s.fmtCalls.ContainsPkgCallExpr(arg, c, false); fmtNode != nil {
					return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewStringFormattedQuery creates a new rule which detects string-formatted SQL queries
func NewStringFormattedQuery(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	dbCalls := gosec.NewCallList()
	dbCalls.Add("database/sql", "Exec")
	dbCalls.Add("database/sql", "ExecContext")
	dbCalls.Add("database/sql", "Query")
	dbCalls.Add("database/sql", "QueryContext")
	dbCalls.Add("database/sql", "QueryRow")
	dbCalls.Add("database/sql", "QueryRowContext")

	fmtCalls := gosec.NewCallList()
	fmtCalls.Add("fmt", "Sprintf")
	fmtCalls.Add("fmt", "Fprintf")
	fmtCalls.Add("fmt", "Printf")

	return &stringFormattedQuery{
		dbCalls:  dbCalls,
		fmtCalls: fmtCalls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data. Related CWEs: CWE-89, OWASP A01:2017, A03:2021",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}