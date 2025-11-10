/**
 * @name Permissive CORS
 * @description Permissive CORS policy will allow a malicious application to communicate with
 *              the victim application in an inappropriate way, leading to spoofing, data theft,
 *              relay and other attacks.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id java/permissive-cors
 * @tags security
 *       cwe/183
 *       owasp/a04
 */

import java

// Method call patterns for setting insecure CORS headers
predicate isInsecureCorsHeaderCall(Call call) {
  exists(Method m, Literal headerNameArg, Literal headerValueArg |
    headerNameArg instanceof StringLiteral and
    headerValueArg instanceof StringLiteral and
    call.getCallee() = m and
    (
      // Check for addHeader/setHeader calls on HttpServletResponse
      (
        (
          m.getName() = "addHeader" or
          m.getName() = "setHeader"
        ) and
        m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
        (
          headerNameArg = call.getArgument(0) and
          headerNameArg.(StringLiteral).getValue().toLowerCase().matches("%access-control-allow-origin%") and
          headerValueArg = call.getArgument(1) and
          headerValueArg.(StringLiteral).getValue().matches("%^\\*|null$%")
        )
      )
      or
      // Check for add calls on HttpHeaders
      (
        m.getName() = "add" and
        m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
        headerNameArg = call.getArgument(0) and
        headerNameArg.(StringLiteral).getValue().toLowerCase().matches("%access-control-allow-origin%") and
        headerValueArg = call.getArgument(1) and
        headerValueArg.(StringLiteral).getValue().matches("%^\\*|null$%")
      )
    )
  )
}

// Method call patterns for ResponseEntity/ServerResponse builder methods
predicate isInsecureCorsBuilderCall(Call call) {
  exists(Method m, Literal headerNameArg, Literal headerValueArg |
    headerNameArg instanceof StringLiteral and
    headerValueArg instanceof StringLiteral and
    call.getCallee() = m and
    (
      m.getName() = "header" and
      (
        m.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") or
        m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.server", "ServerResponse")
      ) and
      headerNameArg = call.getArgument(0) and
      headerNameArg.(StringLiteral).getValue().toLowerCase().matches("%access-control-allow-origin%") and
      headerValueArg = call.getArgument(1) and
      headerValueArg.(StringLiteral).getValue().matches("%^\\*|null$%")
    )
  )
}

// Collect all insecure CORS header calls
from Call call
where isInsecureCorsHeaderCall(call) or isInsecureCorsBuilderCall(call)
select call, "Insecure CORS configuration detected that allows all origins (wildcard or null). " +
            "This may enable security risks like spoofing, data theft and relay attacks."