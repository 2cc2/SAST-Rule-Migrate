/**
 * @name Unsafe Reflection
 * @description Detects use of Class.forName() with non-constant class names
 * @id unsafe-reflection
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-470
 *       owasp-a03
 */

import java

from MethodAccess call, Expr arg
where
  call.getMethod().getName() = "forName" and
  call.getMethod().getDeclaringType() instanceof TypeClass and
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
  not arg.isCompileTimeConstant()
select call, "Unsafe Reflection: If an attacker can supply values that control which class to instantiate, they may bypass security checks or cause unexpected behavior."