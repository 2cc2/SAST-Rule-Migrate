/**
 * @name Deserialization of user-controlled data
 * @description Deserializing user-controlled data may allow attackers to execute arbitrary code.
 * @kind path-problem
 * @id py/unsafe-deserialization
 * @problem.severity error
 * @security-severity 9.8
 * @sub-severity high
 * @precision high
 * @tags external/cwe/cwe-502
 *       security
 *       serialization
 */

import python
// import semmle.python.security.dataflow.UnsafeDeserializationQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeDeserializationQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "code execution from deserialization" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `UnsafeDeserialization::Configuration` is needed, otherwise
 * `UnsafeDeserializationCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import UnsafeDeserializationCustomizations::UnsafeDeserialization
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeDeserializationCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "code execution from deserialization"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.frameworks.data.ModelsAsData

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "code execution from deserialization"
 * vulnerabilities, as well as extension points for adding your own.
 */
module UnsafeDeserialization {
  /**
   * A data flow source for "code execution from deserialization" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "code execution from deserialization" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "code execution from deserialization" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * DEPRECATED: Use `ActiveThreatModelSource` from Concepts instead!
   */
  deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * An insecure decoding, considered as a flow sink.
   */
  class InsecureDecodingAsSink extends Sink {
    InsecureDecodingAsSink() {
      exists(Decoding d |
        d.mayExecuteInput() and
        this = d.getAnInput()
      )
    }
  }

  private class SinkFromModel extends Sink {
    SinkFromModel() { this = ModelOutput::getASinkNode("unsafe-deserialization").asSink() }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeDeserializationCustomizations.qll ---

private module UnsafeDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "code execution from deserialization" vulnerabilities. */
module UnsafeDeserializationFlow = TaintTracking::Global<UnsafeDeserializationConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeDeserializationQuery.qll ---
// import UnsafeDeserializationFlow::PathGraph

from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink
where UnsafeDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe deserialization depends on a $@.", source.getNode(),
  "user-provided value"
