package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sessionCookieHttpOnly struct {
	issue.MetaData
	options gosec.CallList
}

func (s *sessionCookieHttpOnly) ID() string {
	return s.MetaData.ID
}

func (s *sessionCookieHttpOnly) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := s.options.ContainsPkgCallExpr(n, c, false); node != nil {
		if composite, ok := node.Args[0].(*ast.CompositeLit); ok {
			for _, elt := range composite.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "HttpOnly" {
						if bl, ok := kv.Value.(*ast.Ident); ok && bl.Name == "true" {
							return nil, nil
						}
					}
				}
			}
			return c.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}
	return nil, nil
}

func NewSessionCookieHttpOnly(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("github.com/gorilla/sessions", "Options")
	return &sessionCookieHttpOnly{
		options: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "A session cookie was detected without setting the 'HttpOnly' flag.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}