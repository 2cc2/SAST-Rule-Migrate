/**
 * @name Tainted SQL String
 * @description User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). 
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/tainted-sql-string
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

class UserInputParameter extends DataFlow::ParameterNode {
  UserInputParameter() {
    not this.getType().getName().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)") and
    exists(Annotation a | a = this.getAnAnnotation() |
      a.getType().hasName("RequestBody") or
      a.getType().hasName("PathVariable") or
      a.getType().hasName("RequestParam") or
      a.getType().hasName("RequestHeader") or
      a.getType().hasName("CookieValue")
    )
  }
}

class StringConcatenationCall extends DataFlow::Node {
  StringConcatenationCall() {
    exists(MethodAccess ma |
      ma = this.(MethodAccess).getMethod() and
      (
        ma.getName().matches("concat") or
        ma.getName().matches("append") or
        (ma.getDeclaringType().hasName("String") and ma.getName().matches("format"))
      ) and
      ma.getArgument(0).toString().matches("select%") or
      ma.getArgument(0).toString().matches("delete%") or
      ma.getArgument(0).toString().matches("insert%") or
      ma.getArgument(0).toString().matches("create%") or
      ma.getArgument(0).toString().matches("update%") or
      ma.getArgument(0).toString().matches("alter%") or
      ma.getArgument(0).toString().matches("drop%") and
      not ma.getDeclaringType().getPackage().getName().matches("System") and
      not ma.getDeclaringType().getPackage().getName().matches("LOG")
    )
  }
}

class TaintedSQLConfig extends TaintTracking::Configuration {
  TaintedSQLConfig() { this = "TaintedSQLConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof StringConcatenationCall
  }
}

from TaintedSQLConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "User data flows into this manually-constructed SQL string.", source,
  "User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM)."