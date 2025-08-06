package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureGRPCConnection struct {
	issue.MetaData
	calls gosec.CallList
}

func (i *insecureGRPCConnection) ID() string {
	return i.MetaData.ID
}

func (i *insecureGRPCConnection) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := i.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
	}
	return nil, nil
}

func NewInsecureGRPCConnection(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("google.golang.org/grpc", "WithInsecure")
	return &insecureGRPCConnection{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.High,
			What: "Found an insecure gRPC connection using 'grpc.WithInsecure()'. This creates a connection without encryption to a gRPC server. A malicious attacker could tamper with the gRPC message, which could compromise the machine. Instead, establish a secure connection with an SSL certificate using the 'grpc.WithTransportCredentials()' function.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}