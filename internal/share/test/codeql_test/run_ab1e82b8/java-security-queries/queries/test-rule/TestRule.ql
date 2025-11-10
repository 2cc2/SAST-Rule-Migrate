/**
 * @name String comparison using '=='
 * @description Strings should not be compared with '=='. This is a reference comparison operator.
 *              Use '.equals()' instead.
 * @kind problem
 * @problem.severity warning
 * @id java/no-string-eqeq
 * @tags correctness
 *       java
 */

import java

from BinaryExpr expr
where expr.getOp() = "==" 
  and exists(RefType strType | 
    strType = expr.getRightOperand().getType() and
    strType.hasQualifiedName("java.lang", "String")
  )
  and not(expr.getLeftOperand() instanceof NullLiteral)
select expr, "Strings should not be compared with '=='. Use '.equals()' instead."