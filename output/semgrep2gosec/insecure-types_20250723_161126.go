package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureTemplate struct {
	issue.MetaData
	types []string
}

func (i *insecureTemplate) ID() string {
	return i.MetaData.ID
}

func (i *insecureTemplate) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if decl, ok := n.(*ast.DeclStmt); ok {
		if genDecl, ok := decl.Decl.(*ast.GenDecl); ok && genDecl.Tok.String() == "var" {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, t := range i.types {
						if selector, ok := valueSpec.Type.(*ast.SelectorExpr); ok {
							if typeStr := c.Info.TypeOf(selector).String(); typeStr == t {
								return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

// NewInsecureTemplate creates a rule to detect insecure template types
func NewInsecureTemplate(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &insecureTemplate{
		types: []string{
			"html/template.HTML",
			"html/template.CSS",
			"html/template.HTMLAttr",
			"html/template.JS",
			"html/template.JSStr",
			"html/template.Srcset",
		},
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Usage of insecure template types which are documented as a security risk. See https://golang.org/pkg/html/template/#HTML. CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		},
	}, []ast.Node{(*ast.DeclStmt)(nil)}
}