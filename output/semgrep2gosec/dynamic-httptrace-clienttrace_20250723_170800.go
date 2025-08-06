package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type dynamicHTTPTrace struct {
	issue.MetaData
	calls gosec.CallList
}

func (d *dynamicHTTPTrace) ID() string {
	return d.MetaData.ID
}

func (d *dynamicHTTPTrace) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := d.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 1 {
			traceArg := node.Args[1]
			if ident, ok := traceArg.(*ast.Ident); ok {
				if ident.Obj != nil && ident.Obj.Decl != nil {
					if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
						for _, expr := range assign.Rhs {
							if _, ok := expr.(*ast.CompositeLit); !ok {
								return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
							}
						}
					}
				}
			} else if _, ok := traceArg.(*ast.CompositeLit); !ok {
				return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewDynamicHTTPTrace(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net/http/httptrace", "WithClientTrace")
	return &dynamicHTTPTrace{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Detected potentially dynamic ClientTrace. Dynamic ClientTraces are dangerous because they deserialize function code to run when certain Request events occur, which could lead to code being run without your knowledge. Ensure ClientTrace is statically defined. CWE-913: Improper Control of Dynamically-Managed Code Resources",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}