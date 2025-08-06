package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type commandInjection struct {
	issue.MetaData
	stdinPipe gosec.CallList
	write     gosec.CallList
}

func (c *commandInjection) ID() string {
	return c.MetaData.ID
}

func (c *commandInjection) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	// Check if it's a Write call
	if node := c.write.ContainsPkgCallExpr(n, ctx, false); node != nil {
		// Verify the receiver is from StdinPipe
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Obj != nil {
					// Find the assignment from StdinPipe
					if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
						if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
							if c.stdinPipe.ContainsPkgCallExpr(call, ctx, false) != nil {
								// Check if the argument is not a static string/byte slice
								for _, arg := range node.Args {
									switch arg.(type) {
									case *ast.BasicLit, *ast.UnaryExpr: // skip static literals
										return nil, nil
									case *ast.CallExpr: // skip functions like []byte("static")
										return nil, nil
									case *ast.BinaryExpr: // skip concatenations like "a"+"b"
										return nil, nil
									}
								}
								return ctx.NewIssue(n, c.ID(), c.What, c.Severity, c.Confidence), nil
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewCommandInjection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	stdinPipeCalls := gosec.NewCallList()
	stdinPipeCalls.Add("os/exec", "Cmd.StdinPipe")

	writeCalls := gosec.NewCallList()
	writeCalls.Add("io", "WriteCloser.Write")

	return &commandInjection{
		stdinPipe: stdinPipeCalls,
		write:     writeCalls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected non-static command inside Write. If unverified user data can reach this call site, this is a code injection vulnerability.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}