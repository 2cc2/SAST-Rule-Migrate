/**
 * @name GCM Detection
 * @description Detects usage of GCM mode and checks if IV/nonce is potentially reused.
 * @kind problem
 * @problem.severity warning
 * @id java/gcm-detection
 * @tags security
 *       external/cwe/cwe-323
 *       owasp/a02
 *       audit
 */

import java

// Detect GCM mode initialization
predicate isGCMInitialization(MethodAccess ma) {
  exists(Method m | 
    ma.getMethod() = m and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    ma.getArgument(0).toString() = "\"AES/GCM/NoPadding\""
  )
}

// Detect GCMParameterSpec construction
predicate isGCMParameterSpec(ConstructorCall cc) {
  cc.getConstructedType().hasQualifiedName("javax.crypto.spec", "GCMParameterSpec")
}

from MethodAccess gcmInit, ConstructorCall gcmSpec
where 
  isGCMInitialization(gcmInit) or 
  isGCMParameterSpec(gcmSpec)
select gcmInit, "GCM detected, please check that IV/nonce is not reused. " +
  "An Initialization Vector (IV) should be random and unique to prevent cryptographic vulnerabilities."