package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type unsafeReflection struct {
	issue.MetaData
	methodCalls gosec.CallList
	fieldCalls  gosec.CallList
}

func (u *unsafeReflection) ID() string {
	return u.MetaData.ID
}

func (u *unsafeReflection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for MethodByName calls with non-constant argument
	if node := u.methodCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			if _, ok := node.Args[0].(*ast.BasicLit); !ok {
				return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
			}
		}
	}

	// Check for FieldByName calls with non-constant argument
	if node := u.fieldCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			if _, ok := node.Args[0].(*ast.BasicLit); !ok {
				return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
			}
		}
	}

	return nil, nil
}

func NewUnsafeReflection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	methodCalls := gosec.NewCallList()
	methodCalls.Add("reflect", "MethodByName")

	fieldCalls := gosec.NewCallList()
	fieldCalls.Add("reflect", "FieldByName")

	return &unsafeReflection{
		methodCalls: methodCalls,
		fieldCalls:  fieldCalls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What: "Unsafe reflection usage: MethodByName/FieldByName with non-constant argument may allow " +
				"attackers to bypass authentication or access control checks. CWE-470: Use of " +
				"Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}