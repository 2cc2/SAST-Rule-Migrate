package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type hiddenGoroutine struct {
	issue.MetaData
}

func (h *hiddenGoroutine) ID() string {
	return h.MetaData.ID
}

func (h *hiddenGoroutine) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if funcDecl, ok := n.(*ast.FuncDecl); ok {
		if len(funcDecl.Body.List) == 1 {
			if goStmt, ok := funcDecl.Body.List[0].(*ast.GoStmt); ok {
				if _, ok := goStmt.Call.Fun.(*ast.FuncLit); ok {
					return c.NewIssue(n, h.ID(), h.What, h.Severity, h.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewHiddenGoroutine(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &hiddenGoroutine{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.High,
			What:       "Detected a hidden goroutine. Function invocations are expected to be synchronous, and this function will execute asynchronously because all it does is call a goroutine. Instead, remove the internal goroutine and call the function using 'go'.",
		},
	}, []ast.Node{(*ast.FuncDecl)(nil)}
}