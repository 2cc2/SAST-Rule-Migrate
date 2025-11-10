/**
 * @name Jackson unsafe deserialization - Case 1
 * @description Detection of unsafe Jackson deserialization with default typing
 * @kind path-problem
 * @problem.severity warning
 * @id java/jackson-unsafe-deserialization/case1
 * @tags security
 *       external/cwe/cwe-502
 *       external/owasp/a8
 */
import java
import semmle.code.java.dataflow.FlowSources

from ConstructorCall mapperCall, MethodCall readValueCall, Method readValueMethod, Expr jsonInput
where
  mapperCall.getConstructedType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
  exists(Method enableTyping |
    enableTyping.getName() = "enableDefaultTyping" and
    enableTyping.getDeclaringType() = mapperCall.getConstructedType() and
    exists(MethodCall typingCall |
      typingCall.getMethod() = enableTyping and
      typingCall.getQualifier() = mapperCall
    )
  ) and
  readValueCall.getMethod() = readValueMethod and
  readValueMethod.getName() = "readValue" and
  readValueMethod.getDeclaringType() = mapperCall.getConstructedType() and
  jsonInput = readValueCall.getArgument(0)
select readValueCall, "Unsafe Jackson deserialization with default typing enabled", jsonInput,
  "This readValue call uses ObjectMapper with default typing enabled, which is unsafe."