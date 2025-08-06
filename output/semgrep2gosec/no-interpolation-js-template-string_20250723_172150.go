package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type jsTemplateInterpolation struct {
	issue.MetaData
}

func (j *jsTemplateInterpolation) ID() string {
	return j.MetaData.ID
}

func (j *jsTemplateInterpolation) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if template, ok := n.(*ast.BasicLit); ok && template.Kind.String() == "STRING" {
		if len(template.Value) > 0 && template.Value[0] == '`' {
			// Check for template interpolation pattern "{{...}}"
			for i := 1; i < len(template.Value)-1; i++ {
				if template.Value[i] == '{' && i+1 < len(template.Value)-1 && template.Value[i+1] == '{' {
					return c.NewIssue(n, j.ID(), j.What, j.Severity, j.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewJsTemplateInterpolation(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &jsTemplateInterpolation{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What: "Detected template variable interpolation in JavaScript template string (CWE-79). " +
				"This is potentially vulnerable to XSS attacks. Obtain variables outside " +
				"of template string and ensure proper escaping. References: " +
				"https://github.com/golang/go/issues/9200#issuecomment-66100328, " +
				"https://blogtitle.github.io/robn-go-security-pearls-cross-site-scripting-xss/",
		},
	}, []ast.Node{(*ast.BasicLit)(nil)}
}