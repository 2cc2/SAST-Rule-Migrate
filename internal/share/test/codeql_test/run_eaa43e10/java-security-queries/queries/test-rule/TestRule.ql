/**
 * @name Potential Reverse Shell Behavior
 * @description Detects potential reverse shell creation using Socket or ProcessBuilder
 * @kind path-problem
 * @problem.severity warning
 * @id java/reverse-shell
 * @tags security
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 *       owasp-a1
 *       owasp-a3
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

predicate isReverseShellSocket(DataFlow::Node source, DataFlow::Node sink) {
  exists(MethodAccess ma, MethodAccess getInput, MethodAccess available, MethodAccess read, MethodAccess flush |
    // Socket creation pattern
    ma.getMethod().hasName("Socket") and
    source.asExpr() = ma and
    
    // Get InputStream from socket
    getInput.getMethod().hasName("getInputStream") and
    getInput.getQualifier() = ma and
    
    // Check available() > 0
    available.getMethod().hasName("available") and
    available.getQualifier() = getInput and
    
    // Read from stream
    read.getMethod().hasName("read") and
    read.getQualifier() = getInput and
    
    // Flush output
    flush.getMethod().hasName("flush") and
    
    // Data flow from Socket to flush
    TaintTracking::localTaint(source, sink)
  )
}

predicate isReverseShellProcess(DataFlow::Node source, DataFlow::Node sink) {
  exists(MethodAccess ma, MethodAccess destroy |
    // ProcessBuilder creation
    ma.getMethod().hasName("start") and
    ma.getQualifier().getType().hasName("ProcessBuilder") and
    source.asExpr() = ma and
    
    // Process destruction
    destroy.getMethod().hasName("destroy") and
    
    // Data flow from Process to destroy
    TaintTracking::localTaint(source, sink)
  )
}

from DataFlow::Node source, DataFlow::Node sink
where 
  isReverseShellSocket(source, sink) or 
  isReverseShellProcess(source, sink)
select sink, "Potential reverse shell behavior detected", source, 
  "This code may create a reverse shell connection ($@ could flow here).", source, "Creation point"