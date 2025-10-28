/**
 * @name eval-detected
 * @description Detected the use of eval(). eval() can be dangerous if used to evaluate
 *              dynamic content. If this content can be input from outside the program,
 *              this may be a code injection vulnerability. Ensure evaluated content is
 *              not definable by external sources.
 * @kind problem
 * @problem.severity warning
 * @id py/eval-detected
 * @tags security
 *       external/cwe/cwe-094
 */

import python

// Define eval() calls
private class EvalCall extends Call {
  EvalCall() {
    this.getFunc().(Name).getId() = "eval"
  }
}

// Define literal sanitizers
private class LiteralArg extends Expr {
  LiteralArg() {
    exists(Str str | str = this)
  }
}

// Define safe literal barriers
private class SafeLiteral extends Str {
  SafeLiteral() {
    this.getText().regexpMatch("^\\w+$")
  }
}

from EvalCall call, Expr arg
where
  arg = call.getArg(0) and
  not exists(SafeLiteral safe | safe = arg) and
  not exists(LiteralArg literal | literal = arg)
select call, "Detected the use of eval(). eval() can be dangerous if used to evaluate " +
  "dynamic content. If this content can be input from outside the program, this may " +
  "be a code injection vulnerability."