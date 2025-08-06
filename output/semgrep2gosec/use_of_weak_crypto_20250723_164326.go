package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type weakCrypto struct {
	issue.MetaData
	calls gosec.CallList
	pkg   string
}

func (w *weakCrypto) ID() string {
	return w.MetaData.ID
}

func (w *weakCrypto) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := w.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, w.ID(), w.What, w.Severity, w.Confidence), nil
	}
	return nil, nil
}

// NewWeakCrypto creates rules for detecting weak cryptographic algorithms
func NewWeakCrypto(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	var calls gosec.CallList
	var pkg string
	var what string

	switch id {
	case "use-of-md5":
		calls = gosec.NewCallList()
		calls.Add("crypto/md5", "New")
		calls.Add("crypto/md5", "Sum")
		pkg = "crypto/md5"
		what = "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead."
	case "use-of-sha1":
		calls = gosec.NewCallList()
		calls.Add("crypto/sha1", "New")
		calls.Add("crypto/sha1", "Sum")
		pkg = "crypto/sha1"
		what = "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead."
	case "use-of-DES":
		calls = gosec.NewCallList()
		calls.Add("crypto/des", "NewTripleDESCipher")
		calls.Add("crypto/des", "NewCipher")
		pkg = "crypto/des"
		what = "Detected DES cipher algorithm which is insecure. The algorithm is considered weak and has been deprecated. Use AES instead."
	case "use-of-rc4":
		calls = gosec.NewCallList()
		calls.Add("crypto/rc4", "NewCipher")
		pkg = "crypto/rc4"
		what = "Detected RC4 cipher algorithm which is insecure. The algorithm has many known vulnerabilities. Use AES instead."
	}

	return &weakCrypto{
		calls: calls,
		pkg:   pkg,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       what,
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}