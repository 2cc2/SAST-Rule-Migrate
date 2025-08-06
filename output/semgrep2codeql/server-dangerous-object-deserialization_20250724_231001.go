/**
 * @name Server Dangerous Object Deserialization
 * @description Using an arbitrary object with Java RMI is an insecure deserialization
 *              vulnerability. This object can be manipulated by a malicious actor allowing them 
 *              to execute code on your system.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id java/server-dangerous-object-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       owasp-a08:2017
 *       owasp-a08:2021
 */

import java
import semmle.code.java.dataflow.FlowSources

predicate isDangerousParamType(RefType paramType) {
  not paramType.hasName(["String", "boolean", "Boolean", "byte", "Byte", "char", 
                        "Character", "double", "Double", "float", "Float", 
                        "int", "Integer", "long", "Long", "short", "Short"])
  and not paramType.getQualifiedName().matches("java.lang.(String|Boolean|Byte|Character|Double|Float|Integer|Long|Short)")
}

from RefType remote, Method meth, Parameter param, RefType paramType
where 
  remote.getASupertype*().hasQualifiedName("java.rmi", "Remote") and
  meth.getDeclaringType() = remote and
  param = meth.getAParameter() and
  paramType = param.getType().(RefType) and
  isDangerousParamType(paramType)
select param, "Using "+paramType.toString()+" with Java RMI is an insecure deserialization vulnerability. " +
       "This object can be manipulated by a malicious actor allowing them to execute " +
       "code on your system. Instead, use an integer ID to look up your object, or " +
       "consider alternative serialization schemes such as JSON."