/**
 * @name Detected use of eval()
 * @description Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content.
 *              If this content can be input from outside the program, this may be a code injection vulnerability.
 *              Ensure evaluated content is not definable by external sources.
 * @kind problem
 * @problem.severity warning
 * @id py/eval-detected
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03
 */
import python

from Call call, StringLiteral lit
where
  call.getFuncName() = "eval" and
  call.getArg(0) = lit and
  lit.getValue() != "" and
  lit.getValue() != "..."
select call, "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. " +
  "If this content can be input from outside the program, this may be a code injection vulnerability. " +
  "Ensure evaluated content is not definable by external sources."