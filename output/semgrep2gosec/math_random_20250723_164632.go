package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type weakRandom struct {
	issue.MetaData
	mathRandPkg gosec.CallList
}

func (w *weakRandom) ID() string {
	return w.MetaData.ID
}

func (w *weakRandom) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := w.mathRandPkg.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
	}

	if selector, ok := n.(*ast.SelectorExpr); ok {
		if ident, ok := selector.X.(*ast.Ident); ok {
			if ident.Name == "rand" && w.mathRandPkg.Contains("math/rand", ident.Name) {
				return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
			}
		}
	}

	return nil, nil
}

// NewMathRandomUsed detects usage of math/rand package
func NewMathRandomUsed(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	mathRandPkg := gosec.NewCallList()
	mathRandPkg.Add("math/rand", "Int")
	mathRandPkg.Add("math/rand", "Intn")
	mathRandPkg.Add("math/rand", "Int31")
	mathRandPkg.Add("math/rand", "Int31n")
	mathRandPkg.Add("math/rand", "Int63")
	mathRandPkg.Add("math/rand", "Int63n")
	mathRandPkg.Add("math/rand", "Float32")
	mathRandPkg.Add("math/rand", "Float64")
	mathRandPkg.Add("math/rand", "Read")
	mathRandPkg.Add("math/rand", "New")
	mathRandPkg.Add("math/rand", "NewSource")
	mathRandPkg.Add("math/rand", "Seed")
	mathRandPkg.Add("math/rand", "NormFloat64")
	mathRandPkg.Add("math/rand", "ExpFloat64")

	return &weakRandom{
		mathRandPkg: mathRandPkg,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Do not use math/rand. Use crypto/rand instead. CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
		},
	}, []ast.Node{(*ast.CallExpr)(nil), (*ast.SelectorExpr)(nil)}
}