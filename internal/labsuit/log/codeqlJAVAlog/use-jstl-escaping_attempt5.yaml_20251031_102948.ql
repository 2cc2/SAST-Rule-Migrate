/** 
 * @name Use JSTL escaping
 * @description Detected an Expression Language segment in a tag that does not escape output.
 * @id use-jstl-escaping
 * @kind problem
 * @security-severity 8.8
 * @tags security
 *       jsp
 * @problem.severity warning
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

predicate isUnsafeExpression(Expr expr) {
  exists(CompileTimeConstantExpr cte |
    cte = expr and
    cte.getStringValue().regexpMatch("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>")
  )
}

predicate isXSSSink(Expr expr) {
  exists(CompileTimeConstantExpr cte |
    cte = expr and
    cte.getStringValue().regexpMatch("\\$\\{.*?\\}")
  )
}

from Expr unsafeExpr, Expr xssSink
where isUnsafeExpression(unsafeExpr) and isXSSSink(xssSink)
select xssSink, "Detected an Expression Language segment in a tag that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled externally, " +
  "it is a cross-site scripting vulnerability. Instead, use the 'out' tag from the JSTL " +
  "taglib to escape this expression."