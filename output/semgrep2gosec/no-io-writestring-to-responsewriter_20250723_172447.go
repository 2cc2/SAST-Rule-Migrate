package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type ioWriteStringToRespWriter struct {
	issue.MetaData
	calls gosec.CallList
	responseWriterType *types.Interface
}

func (i *ioWriteStringToRespWriter) ID() string {
	return i.MetaData.ID
}

func (i *ioWriteStringToRespWriter) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := i.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 1 {
			writer := node.Args[0]
			var tv types.TypeAndValue
			var ok bool

			switch v := writer.(type) {
			case *ast.Ident:
				tv, ok = c.Info.Types[v]
			case *ast.SelectorExpr:
				tv, ok = c.Info.Types[v.X]
			}

			if ok && tv.IsValue() {
				if types.Implements(tv.Type, i.responseWriterType) || 
				   types.Implements(types.NewPointer(tv.Type), i.responseWriterType) {
					return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewIoWriteStringToResponseWriter(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("io", "WriteString")

	// Create ResponseWriter interface type
	params := types.NewTuple(
		types.NewVar(0, nil, "b", types.NewSlice(types.Typ[types.Byte])),
	)
	results := types.NewTuple(
		types.NewVar(0, nil, "", types.Typ[types.Int]),
		types.NewVar(0, nil, "", types.Universe.Lookup("error").Type()),
	)

	writeSig := types.NewSignatureType(nil, nil, nil, params, results, false)
	writeHeaderSig := types.NewSignatureType(nil, nil, nil, 
		types.NewTuple(types.NewVar(0, nil, "code", types.Typ[types.Int])), 
		nil, false)

	responseWriterType := types.NewInterfaceType(
		[]*types.Func{
			types.NewFunc(0, nil, "Header", nil),
			types.NewFunc(0, nil, "Write", writeSig),
			types.NewFunc(0, nil, "WriteHeader", writeHeaderSig),
		},
		nil,
	).Complete()

	return &ioWriteStringToRespWriter{
		calls: calls,
		responseWriterType: responseWriterType,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Detected 'io.WriteString()' writing directly to 'http.ResponseWriter'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data to users. OWASP: A07:2017 - Cross-Site Scripting (XSS), A03:2021 - Injection. CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}