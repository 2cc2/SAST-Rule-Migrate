package rules

import (
	"go/ast"
	"go/token"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type loopPointer struct {
	issue.MetaData
}

func (l *loopPointer) ID() string {
	return l.MetaData.ID
}

func (l *loopPointer) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if forStmt, ok := n.(*ast.RangeStmt); ok {
		walker := &loopPointerWalker{
			ctx:    c,
			key:    forStmt.Key,
			value:  forStmt.Value,
			meta:   l.MetaData,
			issues: make([]*issue.Issue, 0),
		}
		ast.Walk(walker, forStmt.Body)
		if len(walker.issues) > 0 {
			return walker.issues[0], nil
		}
	}
	return nil, nil
}

type loopPointerWalker struct {
	ctx    *gosec.Context
	key    ast.Expr
	value  ast.Expr
	meta   issue.MetaData
	issues []*issue.Issue
}

func (l *loopPointerWalker) Visit(n ast.Node) ast.Visitor {
	if unary, ok := n.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		if ident, ok := unary.X.(*ast.Ident); ok {
			if ident.Obj != nil {
				if (l.key != nil && ident.Obj.Decl == l.key.(*ast.Ident).Obj.Decl) ||
					(l.value != nil && ident.Obj.Decl == l.value.(*ast.Ident).Obj.Decl) {
					l.issues = append(l.issues, l.ctx.NewIssue(n, l.meta.ID, l.meta.What, l.meta.Severity, l.meta.Confidence))
				}
			}
		}
	}
	return l
}

func NewExportedLoopPointer(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &loopPointer{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Loop pointer may be exported from loop. This pointer is shared between iterations and will always point to the last value. To fix, copy the pointer to a new pointer within the loop.",
		},
	}, []ast.Node{(*ast.RangeStmt)(nil)}
}