/**
 * @name Turbine SQL injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 * if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id turbine-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import DataFlow::PathGraph
import DataFlow::TaintTracking
import semmle.code.java.MethodAccess
import semmle.code.java.Parameter
import semmle.code.java.Literal

class SqlConcatSource extends TaintTracking::Source {
  SqlConcatSource() {
    exists(MethodAccess ma |
      (ma.getMethod().getName().matches("String%.format%") or
       ma.getMethod().getBytecodeSignature() = "% format(java.lang.String,java.lang.Object[])%") or
      ma.getCompileTimeConstant().toString().contains("+")
    )
  }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof MethodAccess and
    exists(MethodAccess ma |
      ma = source.asExpr() |
      (ma.getMethod().getName().matches("String%.format%") or
       ma.getMethod().getBytecodeSignature() = "% format(java.lang.String,java.lang.Object[])%") or
      ma.getCompileTimeConstant().toString().contains("+")
    )
  }
}

class SqlParamSource extends TaintTracking::Source {
  SqlParamSource() { this.toString() = "$SQL" }
  
  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      p = source.asParameter() |
      p.getName() = "$SQL"
    )
  }
}

class SqlSink extends TaintTracking::Sink {
  SqlSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "executeQuery" and
      (ma.getMethod().getDeclaringType().toString().matches("BasePeer") or
       ma.getMethod().getDeclaringType().toString().matches("GroupPeer"))
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma = sink.asExpr() |
      ma.getMethod().getName() = "executeQuery" and
      (ma.getMethod().getDeclaringType().toString().matches("BasePeer") or
       ma.getMethod().getDeclaringType().toString().matches("GroupPeer"))
    )
  }
}

class LiteralSanitizer extends TaintTracking::Sanitizer {
  LiteralSanitizer() {
    exists(Literal lit | lit.toString().matches("\".+\""))
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal lit | lit = sanitizer.asExpr() | lit.toString().matches("\".+\""))
  }
}

class TurbineSQLIRule extends TaintTracking::Configuration {
  TurbineSQLIRule() { this = "turbine-sqli" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlConcatSource or source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof LiteralSanitizer }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      pred.asExpr() = ma.getArgument(_) and
      succ.asExpr() = ma.getQualifier()
    )
  }
}

from TurbineSQLIRule cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."