package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type xmlExternalEntity struct {
	issue.MetaData
	calls gosec.CallList
}

func (x *xmlExternalEntity) ID() string {
	return x.MetaData.ID
}

func (x *xmlExternalEntity) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := x.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, x.ID(), x.What, x.Severity, x.Confidence), nil
	}
	return nil, nil
}

func NewXmlExternalEntity(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("github.com/lestrrat-go/libxml2/parser", "New")
	return &xmlExternalEntity{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Detected enabling of XMLParseNoEnt in libxml2 parser.New() which allows parsing of external entities and can lead to XXE. CWE-611, OWASP A04:2017, OWASP A05:2021",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}