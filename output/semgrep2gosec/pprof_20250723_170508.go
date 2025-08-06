package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type pprofExposure struct {
	issue.MetaData
	calls gosec.CallList
}

func (p *pprofExposure) ID() string {
	return p.MetaData.ID
}

func (p *pprofExposure) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := p.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		// Check if ListenAndServe is not binding to localhost
		if sel, ok := node.Args[0].(*ast.BasicLit); ok {
			if sel.Value != `"localhost"` && sel.Value != `"127.0.0.1"` {
				return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewPprofExposure(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net/http", "ListenAndServe")
	return &pprofExposure{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.Low,
			What:       "The profiling 'pprof' endpoint is automatically exposed on /debug/pprof. This could leak information about the server. Instead, use `import \"net/http/pprof\"`. See https://www.farsightsecurity.com/blog/txt-record/go-remote-profiling-20161028/ for more information and mitigation.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}