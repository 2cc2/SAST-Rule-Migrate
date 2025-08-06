/**
 * @name Dangerous Groovy Shell Usage
 * @description Detects unsafe usage of GroovyShell/GroovyClassLoader methods with dynamic inputs
 * @kind problem
 * @problem.severity warning
 * @id java/dangerous-groovy-shell
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 *       cwe2022-top25
 */

import java

from 
  MethodCall ma,
  Expr receiver,
  string methodName
where
  (methodName = "parse" or methodName = "evaluate" or methodName = "parseClass") and
  ma.getMethod().hasName(methodName) and
  (
    exists(ClassInstanceExpr cie | 
      cie.getConstructedType().(RefType).hasQualifiedName("groovy.lang", "GroovyShell") and
      receiver = cie
    ) 
    or
    exists(ClassInstanceExpr cie | 
      cie.getConstructedType().(RefType).hasQualifiedName("groovy.lang", "GroovyClassLoader") and
      receiver = cie
    )
  ) and
  not ma.getArgument(0) instanceof StringLiteral and
  receiver = ma.getQualifier()
select ma, 
  "A Groovy expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."