package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type xssResponseWriter struct {
	issue.MetaData
	responseWriter gosec.CallList
	printfFuncs    gosec.CallList
	queryMethods   gosec.CallList
}

func (x *xssResponseWriter) ID() string {
	return x.MetaData.ID
}

func (x *xssResponseWriter) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for ResponseWriter.Write() with fmt.Printf calls containing URL query params
	if callExpr := x.responseWriter.ContainsPkgCallExpr(n, c, false); callExpr != nil {
		if len(callExpr.Args) > 0 {
			arg := callExpr.Args[0]
			if arg, ok := arg.(*ast.CallExpr); ok {
				if len(arg.Args) > 0 {
					if selExpr, ok := arg.Fun.(*ast.SelectorExpr); ok {
						if x.printfFuncs.Contains(selExpr.X.(*ast.Ident).Name, selExpr.Sel.Name) {
							// Check if any argument comes from URL query parameters
							for _, printfArg := range arg.Args {
								if x.isFromQueryParam(printfArg, c) {
									return c.NewIssue(n, x.ID(), x.What, x.Severity, x.Confidence), nil
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func (x *xssResponseWriter) isFromQueryParam(n ast.Node, c *gosec.Context) bool {
	if ident, ok := n.(*ast.Ident); ok && ident.Obj != nil {
		if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
			if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if x.queryMethods.Contains(c.Info.TypeOf(sel.X).String(), sel.Sel.Name) {
						return true
					}
				}
			}
			// Check for direct URL.Query() access
			for _, rhs := range assign.Rhs {
				if call, ok := rhs.(*ast.IndexExpr); ok {
					if sel, ok := call.X.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "Query" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func NewXSSResponseWriter(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	responseWriter := gosec.NewCallList()
	responseWriter.Add("http", "ResponseWriter.Write")

	printfFuncs := gosec.NewCallList()
	printfFuncs.Add("fmt", "Printf")
	printfFuncs.Add("fmt", "Sprintf")
	printfFuncs.Add("fmt", "Fprintf")

	queryMethods := gosec.NewCallList()
	queryMethods.Add("net/url", "Values.Get")

	return &xssResponseWriter{
		responseWriter: responseWriter,
		printfFuncs:    printfFuncs,
		queryMethods:   queryMethods,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Found data going from URL query parameters into formatted data written to ResponseWriter. This could be XSS and should not be done. If you must do this, ensure your data is sanitized or escaped. CWE-79, OWASP A07:2017, OWASP A03:2021",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}