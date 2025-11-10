/**
 * @name Insecure Trust Manager
 * @description Detected empty trust manager implementations that accept any certificate,
 *              making the system vulnerable to man-in-the-middle attacks.
 * @kind path-problem
 * @problem.severity warning
 * @id java/insecure-trust-manager
 * @tags security
 *       external/cwe/cwe-295
 *       external/owasp/a03
 *       external/owasp/a07
 */

import java

class X509TrustManager extends RefType {
  X509TrustManager() {
    this.hasQualifiedName("javax.net.ssl", "X509TrustManager") or
    this.hasQualifiedName("javax.net.ssl", "X509ExtendedTrustManager")
  }
}

class TrustManagerImplementation extends Class {
  TrustManagerImplementation() {
    this.getASupertype() instanceof X509TrustManager
  }
}

class EmptyTrustManagerMethod extends Method {
  EmptyTrustManagerMethod() {
    (
      this.getDeclaringType() instanceof TrustManagerImplementation or
      this.getDeclaringType().(AnonymousClass).getASupertype() instanceof X509TrustManager
    ) and
    (
      (
        this.getName() = "checkClientTrusted" and
        this.getNumberOfParameters() > 0 and
        not exists(this.getBody().getAChild())
      ) or
      (
        this.getName() = "checkServerTrusted" and
        this.getNumberOfParameters() > 0 and
        not exists(this.getBody().getAChild())
      ) or
      (
        this.getName() = "getAcceptedIssuers" and
        exists(ReturnStmt ret | 
          ret.getResult().(Literal).getValue() = "null" or
          not exists(ret.getResult())
        )
      )
    )
  }
}

from EmptyTrustManagerMethod method
select method, 
  "Detected empty trust manager implementation. This is dangerous because it accepts any certificate, " +
  "enabling man-in-the-middle attacks. Consider using a KeyStore and TrustManagerFactory instead."