/**
 * @name CSV Writer Injection
 * @description Detected user input into a generated CSV file using the built-in `csv` module.
 * @kind path-problem
 * @problem.severity error
 * @id python/csv-writer-injection
 * @tags security
 *       external/cwe/cwe-1236
 */

import python
import semmle.python.security.dataflow.external.TaintTracking
import semmle.python.security.ApiGraphs
import DataFlow::PathGraph

class CSVWriterSink extends DataFlow::Node {
  CSVWriterSink() {
    exists(MethodAccess ma |
      ma.getTarget().hasQualifiedName("csv._Writer", "writerow") or
      ma.getTarget().hasQualifiedName("csv._Writer", "writerows") or
      ma.getTarget().hasQualifiedName("csv._Writer", "writeheader") |
      this.asExpr() = ma
    )
  }
}

class FlaskUserInput extends DataFlow::Node {
  FlaskUserInput() {
    exists(ModuleImport mi | mi.getName() = "flask" |
      exists(MethodAccess ma |
        (
          ma.getTarget().hasQualifiedName("flask.request", "form.get") or
          ma.getTarget().hasQualifiedName("flask.request", "form.__getitem__") or
          ma.getTarget().hasQualifiedName("flask.request", "args.get") or
          ma.getTarget().hasQualifiedName("flask.request", "args.__getitem__") or
          ma.getTarget().hasQualifiedName("flask.request", "values.get") or
          ma.getTarget().hasQualifiedName("flask.request", "values.__getitem__") or
          ma.getTarget().hasQualifiedName("flask.request", "cookies.get") or
          ma.getTarget().hasQualifiedName("flask.request", "cookies.__getitem__") or
          ma.getTarget().hasQualifiedName("flask.request", "stream") or
          ma.getTarget().hasQualifiedName("flask.request", "headers.get") or
          ma.getTarget().hasQualifiedName("flask.request", "headers.__getitem__") or
          ma.getTarget().hasQualifiedName("flask.request", "data") or
          ma.getTarget().hasQualifiedName("flask.request", "full_path") or
          ma.getTarget().hasQualifiedName("flask.request", "url") or
          ma.getTarget().hasQualifiedName("flask.request", "json") or
          ma.getTarget().hasQualifiedName("flask.request", "get_json")
        ) |
        this.asExpr() = ma
      )
    )
  }
}

class RouteParameter extends DataFlow::Node {
  RouteParameter() {
    exists(Function f | f.isRoute() | this.asParameter() = f.getAParameter())
  }
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof FlaskUserInput or source instanceof RouteParameter
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CSVWriterSink
  }

  predicate isSanitizer(DataFlow::Node node) {
    none()
  }
}

module TaintTracking = TaintTracking::Global<TaintConfig>;
module CSVInjection = TaintTracking::PathGraph<TaintConfig>;

from DataFlow::PathNode source, DataFlow::PathNode sink, CSVInjection p
where p.hasFlowPath(source, sink)
select sink, source,
  "Detected user input into a generated CSV file using the built-in `csv` module. " +
  "If user data is used to generate the data in this file, it is possible that an " +
  "attacker could inject a formula when the CSV is imported into a spreadsheet " +
  "application that runs an attacker script."