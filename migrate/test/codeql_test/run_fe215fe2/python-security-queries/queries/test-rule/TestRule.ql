/**
 * @name NaN Injection
 * @description Found user input going directly into typecast for bool(), float(), or complex().
 *              This allows an attacker to inject Python's not-a-number (NaN) into the typecast.
 * @kind path-problem
 * @problem.severity error
 * @id python/nan-injection
 */

import python
import semmle.python.security.TaintTracking
import DataFlow::PathGraph

class FlaskUserInput extends DataFlow::Source::Range {
  FlaskUserInput() {
    exists(MethodCall mc |
      mc.getTarget().getName() = "get" and
      mc.getTarget().getDeclaringClass().getName() = "request" and
      mc.getTarget().getDeclaringClass().getAPackage().getName() = "flask"
      or
      mc.getTarget().getName() = "__getitem__" and
      mc.getTarget().getDeclaringClass().getName() = "request" and
      mc.getTarget().getDeclaringClass().getAPackage().getName() = "flask"
    |
      this = mc
    )
  }
}

class RouteParameter extends DataFlow::Source::Range {
  RouteParameter() {
    exists(Function f, Decorator d |
      d.getTarget().getName() = "route" and
      // CodeQL currently doesn't have direct decorator parameter mapping,
      // this is a placeholder for the actual implementation
      false
    |
      result = f.getAParameter()
    )
  }
}

class NumericTypeCast extends DataFlow::Sink::Range {
  NumericTypeCast() {
    exists(MethodCall mc |
      (mc.getTarget().getName() = "float" or
       mc.getTarget().getName() = "bool" or
       mc.getTarget().getName() = "complex") and
      mc.getTarget().getDeclaringClass().getName() = "builtins"
    |
      this = mc
    )
  }
}

class AnyFunctionCallSanitizer extends DataFlow::Sanitizer::Range {
  AnyFunctionCallSanitizer() {
    exists(MethodCall mc |
      this = mc
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "NaN Injection" }

  override predicate isSource(DataFlow::Source source) {
    source instanceof FlaskUserInput or
    source instanceof RouteParameter
  }

  override predicate isSink(DataFlow::Sink sink) {
    sink instanceof NumericTypeCast
  }

  override predicate isSanitizer(DataFlow::Sanitizer sanitizer) {
    sanitizer instanceof AnyFunctionCallSanitizer
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink,
  "Found user input going directly into numeric type cast ($@). This allows an attacker to inject NaN values.",
  source.getNode(), "User input",
  sink.getNode(), "Type cast"