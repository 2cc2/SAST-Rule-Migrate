/**
 * @name Command Injection in Runtime Calls
 * @description Formatted or concatenated strings as input to java.lang.Runtime calls
 *              could lead to command injection if user input is not sanitized.
 * @kind path-problem
 * @problem.severity error
 * @id java/command-injection-runtime-call
 * @tags security
 *       external/cwe/cwe-78
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class RuntimeCall extends Call {
  RuntimeCall() {
    exists(Method m | 
      m.hasName(["exec", "loadLibrary"]) and
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      this.getCallee() = m
    )
  }
}

class RuntimeSource extends DataFlow::Node {
  RuntimeSource() {
    exists(Expr e |
      (e instanceof AddExpr or
       exists(Call c |
         c.getCallee().hasName(["format"]) and 
         c.getCallee().getDeclaringType().hasQualifiedName("java.lang", "String") and
         e = c
       )) and
      this.asExpr() = e
    )
  }
}

class ShellCommandPattern extends DataFlow::Node {
  ShellCommandPattern() {
    exists(StringLiteral lit |
      lit.getValue().regexpMatch(".*/(sh|bash|ksh|csh|tcsh|zsh)/.*") and
      this.asExpr() = lit
    )
  }
}

class RuntimeShellSink extends DataFlow::Node {
  RuntimeShellSink() {
    exists(RuntimeCall rc, Expr arg |
      (exists(StringLiteral lit | 
         lit.getValue().regexpMatch(".*/(sh|bash|ksh|csh|tcsh|zsh)/.*") and
         (arg = lit or
          exists(ArrayInit ai | arg = ai and ai.getAnInit() = lit) or
          exists(Call c | 
            c.getCallee().hasName(["asList"]) and 
            c.getCallee().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
            arg = c and c.getAnArgument() = lit
          ))
       )) and
      (rc.getAnArgument() = arg or
       rc.getAnArgument().(Call).getAnArgument() = arg) and
      this.asExpr() = arg
    )
  }
}

class RuntimeConfig extends TaintTracking::Configuration {
  RuntimeConfig() { this = "RuntimeConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof RuntimeSource or
    source instanceof ShellCommandPattern
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink instanceof RuntimeShellSink or
    exists(RuntimeCall rc | sink.asExpr() = rc.getAnArgument())
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral lit | lit = sanitizer.asExpr())
  }
}

from RuntimeConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential command injection in Runtime call from unverified input"