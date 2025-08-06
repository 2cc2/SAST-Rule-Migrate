package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sessionCookieSameSiteNone struct {
	issue.MetaData
	options gosec.CallList
}

func (s *sessionCookieSameSiteNone) ID() string {
	return s.MetaData.ID
}

func (s *sessionCookieSameSiteNone) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := s.options.ContainsPkgCallExpr(n, c, false); node != nil {
		if composite, ok := node.Args[0].(*ast.CompositeLit); ok {
			for _, elt := range composite.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "SameSite" {
						if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
							if x, ok := sel.X.(*ast.Ident); ok && x.Name == "http" && sel.Sel.Name == "SameSiteNoneMode" {
								return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewSessionCookieSameSiteNone(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	options := gosec.NewCallList()
	options.Add("github.com/gorilla/sessions", "NewCookieStore")
	options.Add("github.com/gorilla/sessions", "NewFilesystemStore")

	return &sessionCookieSameSiteNone{
		options: options,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Found SameSiteNoneMode setting in Gorilla session options. Consider setting SameSite to Lax, Strict or Default for enhanced security.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}