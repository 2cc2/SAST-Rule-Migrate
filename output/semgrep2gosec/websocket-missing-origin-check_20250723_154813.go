package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type websocketOriginCheck struct {
	issue.MetaData
	upgradeCall gosec.CallList
	initCheck   gosec.CallList
	assignCheck gosec.CallList
}

func (w *websocketOriginCheck) ID() string {
	return w.MetaData.ID
}

func (w *websocketOriginCheck) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	switch node := n.(type) {
	case *ast.CompositeLit:
		if w.initCheck.ContainsPkgCallExpr(node, c, false) != nil {
			if !checksForOriginCheck(node) {
				return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
			}
		}
	case *ast.AssignStmt:
		for _, expr := range node.Lhs {
			if selector, ok := expr.(*ast.SelectorExpr); ok {
				if w.assignCheck.ContainsPkgCallExpr(selector, c, false) != nil {
					return nil, nil
				}
			}
		}
	case *ast.CallExpr:
		if w.upgradeCall.ContainsPkgCallExpr(node, c, false) != nil {
			return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
		}
	}
	return nil, nil
}

func checksForOriginCheck(node *ast.CompositeLit) bool {
	for _, elt := range node.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "CheckOrigin" {
				return true
			}
		}
	}
	return false
}

func NewWebsocketOriginCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	upgradeCall := gosec.NewCallList()
	upgradeCall.Add("github.com/gorilla/websocket", "Upgrader.Upgrade")

	initCheck := gosec.NewCallList()
	initCheck.Add("github.com/gorilla/websocket", "Upgrader")

	assignCheck := gosec.NewCallList()
	assignCheck.Add("github.com/gorilla/websocket", "Upgrader.CheckOrigin")

	return &websocketOriginCheck{
		upgradeCall: upgradeCall,
		initCheck:   initCheck,
		assignCheck: assignCheck,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Potential CSRF vulnerability in websocket upgrade - missing Origin header check",
		},
	}, []ast.Node{(*ast.CallExpr)(nil), (*ast.CompositeLit)(nil), (*ast.AssignStmt)(nil)}
}