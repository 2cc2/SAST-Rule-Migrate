/**
 * @name Assignment in Comparison
 * @description Detects when a value is assigned in a conditional test instead of being compared.
 * @kind problem
 * @problem.severity error
 * @id java/assignment-comparison
 * @tags correctness
 */

import java

predicate isAssignmentInIf(IfStmt ifStmt) {
  exists(BinaryExpr binExp |
    binExp = ifStmt.getCondition() and
    binExp.getOp().toString() = "=" and
    (binExp.getLeftOperand() instanceof BooleanLiteral or binExp.getRightOperand() instanceof BooleanLiteral)
  )
}

from IfStmt ifStmt
where isAssignmentInIf(ifStmt)
select ifStmt, "The value is being assigned instead of compared in the conditional test"