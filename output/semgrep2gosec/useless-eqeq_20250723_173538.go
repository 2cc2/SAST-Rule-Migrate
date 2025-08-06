package rules

import (
	"go/ast"
	"go/token"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type eqeqCheck struct {
	issue.MetaData
}

func (e *eqeqCheck) ID() string {
	return e.MetaData.ID
}

func (e *eqeqCheck) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if binaryExpr, ok := n.(*ast.BinaryExpr); ok {
		if x, ok := binaryExpr.X.(*ast.Ident); ok && x != nil {
			if y, ok := binaryExpr.Y.(*ast.Ident); ok && y != nil {
				if x.Name == y.Name && (binaryExpr.Op == token.EQL || binaryExpr.Op == token.NEQ) {
					return c.NewIssue(n, e.ID(), "Detected useless comparison operation `"+x.Name+" "+binaryExpr.Op.String()+" "+y.Name+"`. This will always return 'True' or 'False' and therefore is not necessary. Instead, remove this comparison operation or use another comparison expression that is not deterministic.", e.Severity, issue.High), nil
				}
			}
		}
	}
	return nil, nil
}

type hardcodedIfCheck struct {
	issue.MetaData
}

func (h *hardcodedIfCheck) ID() string {
	return h.MetaData.ID
}

func (h *hardcodedIfCheck) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if ifStmt, ok := n.(*ast.IfStmt); ok {
		if ident, ok := ifStmt.Cond.(*ast.Ident); ok {
			if ident.Name == "true" || ident.Name == "false" {
				return c.NewIssue(n, h.ID(), "Detected useless if statement. 'if ("+ident.Name+")' always result in the same behavior, and therefore is not necessary in the code. Remove the 'if ("+ident.Name+")' expression completely.", h.Severity, issue.High), nil
			}
		}
	}
	return nil, nil
}

func NewEqeqCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &eqeqCheck{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.High,
			What:       "Useless comparison operation detected. Category: correctness",
		},
	}, []ast.Node{(*ast.BinaryExpr)(nil)}
}

func NewHardcodedIfCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &hardcodedIfCheck{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.High,
			What:       "Useless if statement detected. Category: correctness",
		},
	}, []ast.Node{(*ast.IfStmt)(nil)}
}