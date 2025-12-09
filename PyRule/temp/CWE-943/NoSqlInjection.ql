/**
 * @name NoSQL Injection
 * @description Building a NoSQL query from user-controlled sources is vulnerable to insertion of
 *              malicious NoSQL code by the user.
 * @kind path-problem
 * @precision high
 * @problem.severity error
 * @security-severity 8.8
 * @id py/nosql-injection
 * @tags security
 *       external/cwe/cwe-943
 */

import python
// import semmle.python.security.dataflow.NoSqlInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/NoSqlInjectionQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting NoSQL injection vulnerabilities
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
// private import NoSqlInjectionCustomizations::NoSqlInjection as C
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/NoSqlInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "NoSql injection"
 * vulnerabilities, as well as extension points for adding your own.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "NoSql injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module NoSqlInjection {
  private newtype TFlowState =
    TString() or
    TDict()

  /** A flow state, tracking the structure of the data. */
  abstract class FlowState extends TFlowState {
    /** Gets a textual representation of this element. */
    abstract string toString();
  }

  /** A state where the tracked data is only a string. */
  class String extends FlowState, TString {
    override string toString() { result = "String" }
  }

  /**
   * A state where the tracked data has been converted to
   * a dictionary.
   *
   * We include cases where data represent JSON objects, so
   * it could actually still be just a string. It could
   * also contain query operators, or even JavaScript code.
   */
  class Dict extends FlowState, TDict {
    override string toString() { result = "Dict" }
  }

  /** A source allowing string inputs. */
  abstract class StringSource extends DataFlow::Node { }

  /** A source of allowing dictionaries. */
  abstract class DictSource extends DataFlow::Node { }

  /** A sink vulnerable to user controlled strings. */
  abstract class StringSink extends DataFlow::Node { }

  /** A sink vulnerable to user controlled dictionaries. */
  abstract class DictSink extends DataFlow::Node { }

  /** A data flow node where a string is converted into a dictionary. */
  abstract class StringToDictConversion extends DataFlow::Node {
    /** Gets the argument that specifies the string to be converted. */
    abstract DataFlow::Node getAnInput();

    /** Gets the resulting dictionary. */
    abstract DataFlow::Node getOutput();
  }

  /** A remote flow source considered a source of user controlled strings. */
  class RemoteFlowSourceAsStringSource extends RemoteFlowSource, StringSource { }

  /** A NoSQL query that is vulnerable to user controlled strings. */
  class NoSqlExecutionAsStringSink extends StringSink {
    NoSqlExecutionAsStringSink() {
      exists(NoSqlExecution noSqlExecution | this = noSqlExecution.getQuery() |
        noSqlExecution.vulnerableToStrings()
      )
    }
  }

  /** A NoSQL query that is vulnerable to user controlled dictionaries. */
  class NoSqlExecutionAsDictSink extends DictSink {
    NoSqlExecutionAsDictSink() {
      exists(NoSqlExecution noSqlExecution | this = noSqlExecution.getQuery() |
        noSqlExecution.interpretsDict()
      )
    }
  }

  /** A JSON decoding converts a string to a dictionary. */
  class JsonDecoding extends Decoding, StringToDictConversion {
    JsonDecoding() { this.getFormat() = "JSON" }

    override DataFlow::Node getAnInput() { result = Decoding.super.getAnInput() }

    override DataFlow::Node getOutput() { result = Decoding.super.getOutput() }
  }

  /** A NoSQL decoding interprets a string as a dictionary. */
  class NoSqlDecoding extends Decoding, StringToDictConversion {
    NoSqlDecoding() { this.getFormat() = "NoSQL" }

    override DataFlow::Node getAnInput() { result = Decoding.super.getAnInput() }

    override DataFlow::Node getOutput() { result = Decoding.super.getOutput() }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/NoSqlInjectionCustomizations.qll ---

/**
 * A taint-tracking configuration for detecting NoSQL injection vulnerabilities.
 */
module NoSqlInjectionConfig implements DataFlow::StateConfigSig {
  class FlowState = C::FlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof C::StringSource and
    state instanceof C::String
    or
    source instanceof C::DictSource and
    state instanceof C::Dict
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof C::StringSink and
    (
      state instanceof C::String
      or
      // since Dicts can include strings,
      // e.g. JSON objects can encode strings.
      state instanceof C::Dict
    )
    or
    sink instanceof C::DictSink and
    state instanceof C::Dict
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    // Block `String` paths here, since they change state to `Dict`
    exists(C::StringToDictConversion c | node = c.getOutput()) and
    state instanceof C::String
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
  ) {
    exists(C::StringToDictConversion c |
      nodeFrom = c.getAnInput() and
      nodeTo = c.getOutput()
    ) and
    stateFrom instanceof C::String and
    stateTo instanceof C::Dict
  }

  predicate isBarrier(DataFlow::Node node) {
    node = any(NoSqlSanitizer noSqlSanitizer).getAnInput()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module NoSqlInjectionFlow = TaintTracking::GlobalWithState<NoSqlInjectionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/NoSqlInjectionQuery.qll ---
// import NoSqlInjectionFlow::PathGraph

from NoSqlInjectionFlow::PathNode source, NoSqlInjectionFlow::PathNode sink
where NoSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This NoSQL query contains an unsanitized $@.", source,
  "user-provided value"
