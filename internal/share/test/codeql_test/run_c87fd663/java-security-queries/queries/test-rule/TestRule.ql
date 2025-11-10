/**
 * @name Unsafe SnakeYAML Constructor Usage
 * @description Detects usage of SnakeYAML Yaml() constructor with no arguments,
 *              which is vulnerable to deserialization attacks.
 * @kind path-problem
 * @problem.severity warning
 * @id java/unsafe-snakeyaml-constructor
 * @tags security
 *       external/cwe/cwe-502
 *       owasp-a08:2017
 *       owasp-a08:2021
 *       cwe2021-top25
 *       cwe2022-top25
 */
import java
import semmle.code.java.dataflow.FlowSources

class UnsafeSnakeYAMLConstructor extends MethodAccess {
  UnsafeSnakeYAMLConstructor() {
    this.getMethod().hasQualifiedName("org.yaml.snakeyaml", "Yaml", "<init>") and
    this.getMethod().getNumberOfParameters() = 0
  }
}

class YamlLoadCall extends MethodAccess {
  YamlLoadCall() {
    this.getMethod().hasQualifiedName("org.yaml.snakeyaml", "Yaml", "load")
  }
}

from UnsafeSnakeYAMLConstructor unsafeConstr, YamlLoadCall loadCall, DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink) and
      source.asExpr() = unsafeConstr.getQualifier() and
      sink.asExpr() = loadCall.getQualifier()
select loadCall, "Unsafe SnakeYAML constructor usage. Use Yaml(SafeConstructor) instead to prevent deserialization attacks."