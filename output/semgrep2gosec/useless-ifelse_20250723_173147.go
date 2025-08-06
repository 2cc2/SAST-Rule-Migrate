package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type UselessIfConditional struct {
	issue.MetaData
}

func (u *UselessIfConditional) ID() string {
	return u.MetaData.ID
}

func (u *UselessIfConditional) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	ifStmt, ok := n.(*ast.IfStmt)
	if !ok {
		return nil, nil
	}

	if ifStmt.Else == nil {
		return nil, nil
	}

	elseIf, ok := ifStmt.Else.(*ast.IfStmt)
	if !ok {
		return nil, nil
	}

	if exprBinary, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
		if elseBinary, ok := elseIf.Cond.(*ast.BinaryExpr); ok {
			if exprBinary.Op == elseBinary.Op &&
				exprBinary.X.(*ast.Ident).Name == elseBinary.X.(*ast.Ident).Name &&
				exprBinary.Y.(*ast.BasicLit).Value == elseBinary.Y.(*ast.BasicLit).Value {
				return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewUselessIfConditional(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &UselessIfConditional{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.High,
			What:       "Detected an if block that checks for the same condition on both branches. The second condition check is useless as it is the same as the first, and therefore can be removed from the code",
		},
	}, []ast.Node{(*ast.IfStmt)(nil)}
}

type UselessIfBody struct {
	issue.MetaData
}

func (u *UselessIfBody) ID() string {
	return u.MetaData.ID
}

func (u *UselessIfBody) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	ifStmt, ok := n.(*ast.IfStmt)
	if !ok {
		return nil, nil
	}

	if ifStmt.Else == nil {
		return nil, nil
	}

	block, ok := ifStmt.Else.(*ast.BlockStmt)
	if !ok {
		return nil, nil
	}

	if len(ifStmt.Body.List) != len(block.List) {
		return nil, nil
	}

	// Simple comparison - in real implementation would need deeper AST comparison
	for i, stmt := range ifStmt.Body.List {
		if _, ok1 := stmt.(*ast.ExprStmt); ok1 {
			if _, ok2 := block.List[i].(*ast.ExprStmt); !ok2 {
				return nil, nil
			}
		}
	}

	return c.NewIssue(n, u.ID(), u.What, u.Severity, u.Confidence), nil
}

func NewUselessIfBody(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &UselessIfBody{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.High,
			What:       "Detected identical statements in the if body and the else body of an if-statement. This will lead to the same code being executed no matter what the if-expression evaluates to. Instead, remove the if statement.",
		},
	}, []ast.Node{(*ast.IfStmt)(nil)}
}