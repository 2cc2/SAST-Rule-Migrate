/**
 * @name Use of a broken or weak cryptographic hashing algorithm on sensitive data
 * @description Using broken or weak cryptographic hashing algorithms can compromise security.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id py/weak-sensitive-data-hashing
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-328
 *       external/cwe/cwe-916
 */

import python
// import semmle.python.security.dataflow.WeakSensitiveDataHashingQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/WeakSensitiveDataHashingQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting use of a broken or weak
 * cryptographic hashing algorithm on sensitive data.
 *
 * Note, for performance reasons: only import this file if
 * `WeakSensitiveDataHashing::Configuration` is needed, otherwise
 * `WeakSensitiveDataHashingCustomizations` should be imported instead.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.dataflow.new.SensitiveDataSources

/**
 * Provides a taint-tracking configuration for detecting use of a broken or weak
 * cryptographic hash function on sensitive data, that does NOT require a
 * computationally expensive hash function.
 */
module NormalHashFunction {
  // import WeakSensitiveDataHashingCustomizations::NormalHashFunction
  // --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/WeakSensitiveDataHashingCustomizations.qll ---
  /**
   * Provides default sources, sinks and sanitizers for detecting
   * "use of a broken or weak cryptographic hashing algorithm on sensitive data"
   * vulnerabilities, as well as extension points for adding your own.
   */
  
  private import python
  private import semmle.python.dataflow.new.DataFlow
  private import semmle.python.dataflow.new.TaintTracking
  private import semmle.python.Concepts
  private import semmle.python.dataflow.new.SensitiveDataSources
  private import semmle.python.dataflow.new.BarrierGuards
  
  /**
   * Provides default sources, sinks and sanitizers for detecting
   * "use of a broken or weak cryptographic hashing algorithm on sensitive data"
   * vulnerabilities on sensitive data that does NOT require computationally expensive
   * hashing, as well as extension points for adding your own.
   *
   * Also see the `ComputationallyExpensiveHashFunction` module.
   */
  module NormalHashFunction {
    /**
     * A data flow source for "use of a broken or weak cryptographic hashing algorithm on
     * sensitive data" vulnerabilities.
     */
    abstract class Source extends DataFlow::Node {
      Source() { not this instanceof ComputationallyExpensiveHashFunction::Source }
  
      /** Gets the classification of the sensitive data. */
      abstract string getClassification();
    }
  
    /**
     * A data flow sink for "use of a broken or weak cryptographic hashing algorithm on
     * sensitive data" vulnerabilities.
     */
    abstract class Sink extends DataFlow::Node {
      /**
       * Gets the name of the weak hashing algorithm.
       */
      abstract string getAlgorithmName();
    }
  
    /**
     * A sanitizer for "use of a broken or weak cryptographic hashing algorithm on
     * sensitive data" vulnerabilities.
     */
    abstract class Sanitizer extends DataFlow::Node { }
  
    /**
     * A source of sensitive data, considered as a flow source.
     */
    class SensitiveDataSourceAsSource extends Source, SensitiveDataSource {
      override SensitiveDataClassification getClassification() {
        result = SensitiveDataSource.super.getClassification()
      }
    }
  
    /** The input to a hashing operation using a weak algorithm, considered as a flow sink. */
    class WeakHashingOperationInputSink extends Sink {
      Cryptography::HashingAlgorithm algorithm;
  
      WeakHashingOperationInputSink() {
        exists(Cryptography::CryptographicOperation operation |
          algorithm = operation.getAlgorithm() and
          algorithm.isWeak() and
          this = operation.getAnInput()
        )
      }
  
      override string getAlgorithmName() { result = algorithm.getName() }
    }
  }
  
  /**
   * Provides default sources, sinks and sanitizers for detecting
   * "use of a broken or weak cryptographic hashing algorithm on sensitive data"
   * vulnerabilities on sensitive data that DOES require computationally expensive
   * hashing, as well as extension points for adding your own.
   *
   * Also see the `NormalHashFunction` module.
   */
  module ComputationallyExpensiveHashFunction {
    /**
     * A data flow source of sensitive data that requires computationally expensive
     * hashing for "use of a broken or weak cryptographic hashing algorithm on sensitive
     * data" vulnerabilities.
     */
    abstract class Source extends DataFlow::Node {
      /** Gets the classification of the sensitive data. */
      abstract string getClassification();
    }
  
    /**
     * A data flow sink for sensitive data that requires computationally expensive
     * hashing for "use of a broken or weak cryptographic hashing algorithm on sensitive
     * data" vulnerabilities.
     */
    abstract class Sink extends DataFlow::Node {
      /**
       * Gets the name of the weak hashing algorithm.
       */
      abstract string getAlgorithmName();
  
      /**
       * Holds if this sink is for a computationally expensive hash function (meaning that
       * hash function is just weak in some other regard.
       */
      abstract predicate isComputationallyExpensive();
    }
  
    /**
     * A sanitizer of sensitive data that requires computationally expensive
     * hashing for "use of a broken or weak cryptographic hashing
     * algorithm on sensitive data" vulnerabilities.
     */
    abstract class Sanitizer extends DataFlow::Node { }
  
    /**
     * A source of passwords, considered as a flow source.
     */
    class PasswordSourceAsSource extends Source, SensitiveDataSource {
      PasswordSourceAsSource() {
        SensitiveDataSource.super.getClassification() = SensitiveDataClassification::password()
      }
  
      override SensitiveDataClassification getClassification() {
        result = SensitiveDataSource.super.getClassification()
      }
    }
  
    /**
     * The input to a password hashing operation using a weak algorithm, considered as a
     * flow sink.
     */
    class WeakPasswordHashingOperationInputSink extends Sink {
      Cryptography::CryptographicAlgorithm algorithm;
  
      WeakPasswordHashingOperationInputSink() {
        (
          algorithm instanceof Cryptography::PasswordHashingAlgorithm and
          algorithm.isWeak()
          or
          algorithm instanceof Cryptography::HashingAlgorithm // Note that HashingAlgorithm and PasswordHashingAlgorithm are disjoint
        ) and
        exists(Cryptography::CryptographicOperation operation |
          algorithm = operation.getAlgorithm() and
          this = operation.getAnInput()
        )
      }
  
      override string getAlgorithmName() { result = algorithm.getName() }
  
      override predicate isComputationallyExpensive() {
        algorithm instanceof Cryptography::PasswordHashingAlgorithm
      }
    }
  }
  // --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/WeakSensitiveDataHashingCustomizations.qll ---

  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
      sensitiveDataExtraStepForCalls(node1, node2)
    }

    predicate observeDiffInformedIncrementalMode() { any() }
  }

  /** Global taint-tracking for detecting "use of a broken or weak cryptographic hashing algorithm on sensitive data" vulnerabilities. */
  module Flow = TaintTracking::Global<Config>;
}

/**
 * Provides a taint-tracking configuration for detecting use of a broken or weak
 * cryptographic hashing algorithm on passwords.
 *
 * Passwords has stricter requirements on the hashing algorithm used (must be
 * computationally expensive to prevent brute-force attacks).
 */
module ComputationallyExpensiveHashFunction {
  // import WeakSensitiveDataHashingCustomizations::ComputationallyExpensiveHashFunction

  /**
   * Passwords has stricter requirements on the hashing algorithm used (must be
   * computationally expensive to prevent brute-force attacks).
   */
  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
      sensitiveDataExtraStepForCalls(node1, node2)
    }

    predicate observeDiffInformedIncrementalMode() { any() }
  }

  /** Global taint-tracking for detecting "use of a broken or weak cryptographic hashing algorithm on passwords" vulnerabilities. */
  module Flow = TaintTracking::Global<Config>;
}

/**
 * Global taint-tracking for detecting both variants of "use of a broken or weak
 * cryptographic hashing algorithm on sensitive data" vulnerabilities.
 *
 * See convenience predicates `normalHashFunctionFlowPath` and
 * `computationallyExpensiveHashFunctionFlowPath`.
 */
module WeakSensitiveDataHashingFlow =
  DataFlow::MergePathGraph<NormalHashFunction::Flow::PathNode,
    ComputationallyExpensiveHashFunction::Flow::PathNode, NormalHashFunction::Flow::PathGraph,
    ComputationallyExpensiveHashFunction::Flow::PathGraph>;

/** Holds if data can flow from `source` to `sink` with `NormalHashFunction::Flow`. */
predicate normalHashFunctionFlowPath(
  WeakSensitiveDataHashingFlow::PathNode source, WeakSensitiveDataHashingFlow::PathNode sink
) {
  NormalHashFunction::Flow::flowPath(source.asPathNode1(), sink.asPathNode1())
}

/** Holds if data can flow from `source` to `sink` with `ComputationallyExpensiveHashFunction::Flow`. */
predicate computationallyExpensiveHashFunctionFlowPath(
  WeakSensitiveDataHashingFlow::PathNode source, WeakSensitiveDataHashingFlow::PathNode sink
) {
  ComputationallyExpensiveHashFunction::Flow::flowPath(source.asPathNode2(), sink.asPathNode2())
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/WeakSensitiveDataHashingQuery.qll ---
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import WeakSensitiveDataHashingFlow::PathGraph

from
  WeakSensitiveDataHashingFlow::PathNode source, WeakSensitiveDataHashingFlow::PathNode sink,
  string ending, string algorithmName, string classification
where
  normalHashFunctionFlowPath(source, sink) and
  algorithmName = sink.getNode().(NormalHashFunction::Sink).getAlgorithmName() and
  classification = source.getNode().(NormalHashFunction::Source).getClassification() and
  ending = "."
  or
  computationallyExpensiveHashFunctionFlowPath(source, sink) and
  algorithmName = sink.getNode().(ComputationallyExpensiveHashFunction::Sink).getAlgorithmName() and
  classification =
    source.getNode().(ComputationallyExpensiveHashFunction::Source).getClassification() and
  (
    sink.getNode().(ComputationallyExpensiveHashFunction::Sink).isComputationallyExpensive() and
    ending = "."
    or
    not sink.getNode().(ComputationallyExpensiveHashFunction::Sink).isComputationallyExpensive() and
    ending =
      " for " + classification +
        " hashing, since it is not a computationally expensive hash function."
  )
select sink.getNode(), source, sink,
  "$@ is used in a hashing algorithm (" + algorithmName + ") that is insecure" + ending,
  source.getNode(), "Sensitive data (" + classification + ")"
