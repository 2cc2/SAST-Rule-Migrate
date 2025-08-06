package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureGrpcServer struct {
	issue.MetaData
	calls gosec.CallList
}

func (i *insecureGrpcServer) ID() string {
	return i.MetaData.ID
}

func (i *insecureGrpcServer) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := i.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		// Check if grpc.NewServer has credentials option
		hasCreds := false
		isEmptyConstructor := true
		
		// Check arguments for grpc.ServerOption with Creds
		for _, arg := range node.Args {
			isEmptyConstructor = false
			if call, ok := arg.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "grpc" && sel.Sel.Name == "Creds" {
						hasCreds = true
						break
					}
				}
			}
		}

		// Report issue if no credentials found
		if !hasCreds && (isEmptyConstructor || len(node.Args) > 0) {
			return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
		}
	}
	return nil, nil
}

func NewInsecureGrpcServer(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("google.golang.org/grpc", "NewServer")
	return &insecureGrpcServer{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.High,
			What: "Found an insecure gRPC server without 'grpc.Creds()' or options with credentials. " +
				"This allows for a connection without encryption to this server. " +
				"A malicious attacker could tamper with unprotected gRPC messages. " +
				"Include credentials derived from an SSL certificate to create a secure connection.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}