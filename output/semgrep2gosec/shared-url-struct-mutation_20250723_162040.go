package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sharedURLMutation struct {
	issue.MetaData
	urlFields    []string
	excludedFunc []string
}

func (s *sharedURLMutation) ID() string {
	return s.MetaData.ID
}

func (s *sharedURLMutation) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if assign, ok := n.(*ast.AssignStmt); ok {
		for _, expr := range assign.Lhs {
			if selector, ok := expr.(*ast.SelectorExpr); ok {
				if id, ok := selector.X.(*ast.Ident); ok {
					obj := c.Info.ObjectOf(id)
					if obj != nil {
						// Skip if URL is from new instance creation
						for _, name := range s.excludedFunc {
							if containsCallExpr(c, id.Name, name) {
								return nil, nil
							}
						}
						
						// Check if this is a selector on URL struct
						if _, ok := obj.Type().(*types.Pointer); ok {
							for _, field := range s.urlFields {
								if selector.Sel.Name == field {
									return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
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

func containsCallExpr(c *gosec.Context, varName string, funcName string) bool {
	nodes := c.PkgFiles
	for _, file := range nodes {
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := fun.X.(*ast.Ident); ok && id.Name == "url" && fun.Sel.Name == funcName {
						for _, arg := range call.Args {
							if ident, ok := arg.(*ast.Ident); ok && ident.Name == varName {
								return true
							}
						}
					}
				}
			}
			return true
		})
	}
	return false
}

func NewSharedURLMutation(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &sharedURLMutation{
		urlFields:    []string{"RawQuery", "Path", "RawPath", "Fragment", "RawFragment", "Scheme", "Opaque", "Host", "User"},
		excludedFunc: []string{"Parse", "ParseRequestURI"},
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.Low,
			What:       "Shared URL struct may have been accidentally mutated. Ensure that this behavior is intended. (CWE-436)",
		},
	}, []ast.Node{(*ast.AssignStmt)(nil)}
}