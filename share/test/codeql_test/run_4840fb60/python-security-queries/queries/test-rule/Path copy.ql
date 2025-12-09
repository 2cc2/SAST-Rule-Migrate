/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/path-injection
 * @tags correctness
 *       security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import python
private import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
 
module PathInjection {
    abstract class Source extends DataFlow::Node { }
    abstract class Sink extends DataFlow::Node { }
    abstract class Sanitizer extends DataFlow::Node { }
    private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }
    class FileSystemAccessAsSink extends Sink {
    FileSystemAccessAsSink() {
        this = any(FileSystemAccess e).getAPathArgument() and
       // The same approach is used in the command injection query.
        not exists(Module inStdlib |
        inStdlib.getName() in ["pathlib", "os"] and
        this.getScope().getEnclosingModule() = inStdlib and
         // do allow this call if we're analyzing, say, pathlib.py as part of CPython though
        not exists(inStdlib.getFile().getRelativePath())
       )
     }
   }
 
    private import semmle.python.frameworks.data.ModelsAsData
 
    private class DataAsFileSink extends Sink {
        DataAsFileSink() { this = ModelOutput::getASinkNode("path-injection").asSink() }
    }
   class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }
//    /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
//    deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}

abstract private class NormalizationState extends string {
  bindingset[this]
  NormalizationState() { any() }
}

/** A state signifying that the file path has not been normalized. */
class NotNormalized extends NormalizationState {
  NotNormalized() { this = "NotNormalized" }
}

/** A state signifying that the file path has been normalized, but not checked. */
class NormalizedUnchecked extends NormalizationState {
    NormalizedUnchecked() { this = "NormalizedUnchecked" }
}


module PathInjectionConfig implements DataFlow::StateConfigSig {
    class FlowState = NormalizationState;

    predicate isSource(DataFlow::Node source, FlowState state) {
        source instanceof PathInjection::Source and state instanceof NotNormalized
    }

predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof PathInjection::Sink and
    (
      state instanceof NotNormalized or
      state instanceof NormalizedUnchecked
    )
  }

predicate isBarrier(DataFlow::Node node) { node instanceof PathInjection::Sanitizer }

predicate isBarrier(DataFlow::Node node, FlowState state) {
    // Block `NotNormalized` paths here, since they change state to `NormalizedUnchecked`
    node instanceof Path::PathNormalization and
    state instanceof NotNormalized
    or
    node instanceof Path::SafeAccessCheck and
    state instanceof NormalizedUnchecked
}

predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
) {
    nodeFrom = nodeTo.(Path::PathNormalization).getPathArg() and
    stateFrom instanceof NotNormalized and
    stateTo instanceof NormalizedUnchecked
}

predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "path injection" vulnerabilities. */
module PathInjectionFlow = TaintTracking::GlobalWithState<PathInjectionConfig>;


 
from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
    "user-provided value"
 