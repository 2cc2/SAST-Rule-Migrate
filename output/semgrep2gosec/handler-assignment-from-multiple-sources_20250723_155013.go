package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type handlerAssignment struct {
	issue.MetaData
}

func (h *handlerAssignment) ID() string {
	return h.MetaData.ID
}

func (h *handlerAssignment) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for handler function pattern
	if funcDecl, ok := n.(*ast.FuncDecl); ok {

		var requestParam *ast.Ident
		// Check if it's a HTTP handler by looking for *http.Request parameter
		for _, param := range funcDecl.Type.Params.List {
			if starExpr, ok := param.Type.(*ast.StarExpr); ok {
				if selExpr, ok := starExpr.X.(*ast.SelectorExpr); ok {
					if ident, ok := selExpr.X.(*ast.Ident); ok && ident.Name == "http" && selExpr.Sel.Name == "Request" {
						if len(param.Names) > 0 {
							requestParam = param.Names[0]
							break
						}
					}
				}
			}
		}

		if requestParam != nil {
			// Check for the problematic assignment patterns
			for _, stmt := range funcDecl.Body.List {
				if assignStmt, ok := stmt.(*ast.AssignStmt); ok {
					if len(assignStmt.Rhs) == 1 {
						if rhs, ok := assignStmt.Rhs[0].(*ast.Ident); ok && rhs.Name == requestParam.Name {
							// Check if LHS is from store.Get pattern
							for _, prevStmt := range funcDecl.Body.List {
								if prevAssign, ok := prevStmt.(*ast.AssignStmt); ok && len(prevAssign.Rhs) >= 1 {
									if callExpr, ok := prevAssign.Rhs[0].(*ast.CallExpr); ok {
										if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
											if ident, ok := selExpr.X.(*ast.Ident); ok && (ident.Name == "store" || ident.Obj != nil) && selExpr.Sel.Name == "Get" {
												return c.NewIssue(n, h.ID(), h.What, h.Severity, h.Confidence), nil
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewHandlerAssignmentRule(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &handlerAssignment{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Variable is assigned from two different sources ('store.Get' and 'http.Request'). Make sure this is intended, as this could cause logic bugs if they are treated as the same object.",
		},
	}, []ast.Node{(*ast.FuncDecl)(nil)}
}