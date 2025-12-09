/**
 * @name dynamic-urllib-use-detected
 * @description Detected a dynamic value being used with urllib. urllib supports 'file://' schemes,
 *              so a dynamic value controlled by a malicious actor may allow them to read arbitrary files.
 *              Audit uses of urllib calls to ensure user data cannot control the URLs, or consider
 *              using the 'requests' library instead.
 * @kind taint
 * @problem.severity warning
 * @security-severity 8.0
 * @id py/unsafe-urllib-use
 * @tags security
 *       urllib
 *       file-access
 */

import python
import semmle.python.dataflow.TaintTracking
import DataFlow::PathGraph

class DynamicUrlInput extends DataFlow::Node {
  DynamicUrlInput() {
    exists(Call call |
      not call.getMethodName().matches("urllib\\..*") and
      result.asExpr() = call
    )
  }
}

class UnsafeUrlOpen extends DataFlow::Node {
  UnsafeUrlOpen() {
    exists(Call call |
      call.getMethodName() = ["urlopen", "urlretrieve"] and
      call.getReceiver().getType().hasQualifiedName("urllib") and
      result.asExpr() = call.getArg(0)
    )
    or
    exists(Call call |
      call.getMethodName() = ["open", "retrieve"] and
      call.getReceiver().getType().toString().matches(".*(URLopener|FancyURLopener)") and
      result.asExpr() = call
    )
  }
}

class SafeUrlCalls extends DataFlow::BarrierGuard {
  SafeUrlCalls() {
    exists(Call call |
      call.getMethodName() = ["urlopen", "urlretrieve", "open", "retrieve"] and
      call.getReceiver().getType().hasQualifiedName("urllib") and
      call.getArg(0).getValue().toString().matches("^(?!file://)") and
      result.asExpr() = call
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "dynamic-urllib-use-config" }

  override predicate isSource(DataFlow::Node source) { source instanceof DynamicUrlInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeUrlOpen }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof SafeUrlCalls }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Assignment assign |
      assign.getRhs().getType().toString().matches(".*(URLopener|FancyURLopener)") and
      node1.asExpr() = assign.getRhs() and
      node2.asExpr() = assign.getLhs()
    )
    or
    exists(MethodCall call |
      call.getArgument(0) = node1.asExpr() and
      call.getArgument(1) = node2.asExpr()
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Potential unsafe dynamic URL input using urllib that could allow file access"