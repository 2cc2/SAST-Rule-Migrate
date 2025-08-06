package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sstiDetection struct {
	issue.MetaData
	templateImports gosec.CallList
	requestTypes    []string
}

func (s *sstiDetection) ID() string {
	return s.MetaData.ID
}

func (s *sstiDetection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for template imports
	if node, ok := n.(*ast.ImportSpec); ok {
		if node.Path.Value == "\"html/template\"" {
			return c.NewIssue(node, s.ID(), "html/template package imported", s.Severity, s.Confidence), nil
		}
	}

	// Check for http.Request usage
	if node, ok := n.(*ast.Field); ok {
		if t, ok := node.Type.(*ast.StarExpr); ok {
			if ident, ok := t.X.(*ast.Ident); ok {
				for _, reqType := range s.requestTypes {
					if ident.Name == reqType {
						return c.NewIssue(node, s.ID(), "http.Request usage detected", s.Severity, s.Confidence), nil
					}
				}
			}
		}
	}

	// Check for template parsing with user input
	if node, ok := n.(*ast.CallExpr); ok {
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "template" {
				if sel.Sel.Name == "Parse" {
					return c.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
				}
			}
		}
	}

	return nil, nil
}

func NewSstiDetection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	imports := gosec.NewCallList()
	imports.Add("html/template", "")

	return &sstiDetection{
		templateImports: imports,
		requestTypes:    []string{"Request"},
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Medium,
			What:       "Potential Server-Side Template Injection (SSTI): User input is directly used in template parsing. When using html/template always validate and sanitize user inputs before including in templates. CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
		},
	}, []ast.Node{(*ast.ImportSpec)(nil), (*ast.Field)(nil), (*ast.CallExpr)(nil)}
}