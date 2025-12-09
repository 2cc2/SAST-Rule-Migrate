/**
 * @name Dynamic urllib use detected
 * @description Detected a dynamic value being used with urllib. urllib supports 'file://' schemes,
 *              so a dynamic value controlled by a malicious actor may allow them to read arbitrary files.
 *              Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using 
 *              the 'requests' library instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id python/security/dynamic-urllib-use
 * @tags security
 *       external/cwe/cwe-022
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class DynamicUrlInput extends DataFlow::Node {
  DynamicUrlInput() {
    exists(Call call |
      call.getFuncDecl().getQualifiedName() != "urllib.urlopen" and
      call.getFuncDecl().getQualifiedName() != "urllib.urlretrieve" and
      call.getFuncDecl().getQualifiedName() != "urllib.open" and
      call.getFuncDecl().getQualifiedName() != "urllib.retrieve" and
      this.asExpr() = call
    )
  }

  override predicate isSource() { result = this }

  override predicate hasLocationInfo() { result = true }

  override string toString() { result = "Dynamic URL input" }
}

class UnsafeUrlOpen extends DataFlow::Node {
  UnsafeUrlOpen() {
    exists(Call call |
      (
        call.getFuncDecl().getQualifiedName() = "urllib.urlopen" or
        call.getFuncDecl().getQualifiedName() = "urllib.urlretrieve"
      ) and
      this.asExpr() = call.getArg(0)
    )
    or
    exists(Call call |
      (
        call.getFuncDecl().getName() = "open" or
        call.getFuncDecl().getName() = "retrieve"
      ) and
      call.getReceiver().getType().regexpMatch(".*(URLopener|FancyURLopener)") and
      this.asExpr() = call.getArg(0)
    )
  }

  override predicate isSink() { result = this }

  override predicate hasLocationInfo() { result = true }

  override string toString() { result = "Unsafe URL open" }
}

class SafeUrlCalls extends TaintTracking::Sanitizer {
  SafeUrlCalls() {
    exists(Call call |
      (
        call.getFuncDecl().getQualifiedName() = "urllib.urlopen" or
        call.getFuncDecl().getQualifiedName() = "urllib.urlretrieve" or
        call.getFuncDecl().getName() = "open" or
        call.getFuncDecl().getName() = "retrieve"
      ) and
      call.getArg(0).getStringValue() != "" and
      call.getArg(0).getStringValue().regexpMatches("^(?!file://)") and
      this.asExpr() = call.getArg(0)
    )
  }
}

class UrlOpenerTaint extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    exists(AssignStmt assign |
      assign.getLValue() = node1.asExpr() and
      assign.getRValue().getType().regexpMatch(".*(URLopener|FancyURLopener)") and
      node2.asExpr() = assign.getLValue()
    )
  }
}

class DynamicUrlLibraryUse extends TaintTracking::Configuration {
  DynamicUrlLibraryUse() { this = "DynamicUrlLibraryUse" }

  override predicate isSource(DataFlow::Node source) { source instanceof DynamicUrlInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeUrlOpen }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SafeUrlCalls }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(UrlOpenerTaint taintStep).step(node1, node2)
  }
}

from DynamicUrlLibraryUse cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential unsafe dynamic URL usage detected. $@ flows to $@.",
  source.getNode(), "User input", sink.getNode(), "unsafe URL operation"