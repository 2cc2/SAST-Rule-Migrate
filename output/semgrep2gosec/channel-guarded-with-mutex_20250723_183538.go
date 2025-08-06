package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type guardedChannel struct {
	issue.MetaData
}

func (g *guardedChannel) ID() string {
	return g.MetaData.ID
}

func (g *guardedChannel) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if stmt, ok := n.(*ast.BlockStmt); ok {
		for i := 0; i < len(stmt.List)-2; i++ {
			lock, ok1 := stmt.List[i].(*ast.ExprStmt)
			unlock, ok2 := stmt.List[i+2].(*ast.ExprStmt)
			
			if !ok1 || !ok2 {
				continue
			}

			call1, ok1 := lock.X.(*ast.CallExpr)
			call2, ok2 := unlock.X.(*ast.CallExpr)
			if !ok1 || !ok2 {
				continue
			}

			sel1, ok1 := call1.Fun.(*ast.SelectorExpr)
			sel2, ok2 := call2.Fun.(*ast.SelectorExpr)
			if !ok1 || !ok2 {
				continue
			}

			if sel1.Sel.Name == "Lock" && sel2.Sel.Name == "Unlock" {
				// Check for send operation
				if _, ok := stmt.List[i+1].(*ast.SendStmt); ok {
					return c.NewIssue(n, g.ID(), g.What, g.Severity, g.Confidence), nil
				}
				// Check for receive operation
				if assign, ok := stmt.List[i+1].(*ast.AssignStmt); ok {
					if _, ok := assign.Rhs[0].(*ast.UnaryExpr); ok {
						return c.NewIssue(n, g.ID(), g.What, g.Severity, g.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewGuardedChannel(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &guardedChannel{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.High,
			What:       "Detected a channel guarded with a mutex. Channels already have an internal mutex, so this is unnecessary. Remove the mutex. See https://hackmongo.com/page/golang-antipatterns/#guarded-channel for more information.",
		},
	}, []ast.Node{(*ast.BlockStmt)(nil)}
}