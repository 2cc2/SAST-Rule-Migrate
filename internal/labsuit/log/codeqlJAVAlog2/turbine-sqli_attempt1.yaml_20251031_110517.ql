/** 
 * @name turbine-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @kind problem
 * @problem.severity warning
 * @id java/turbine-sqli
 * @tags security
 *       cwe:89
 *       owasp:a01:2017
 *       owasp:a03:2021
 */

import java

// Sources: String.format calls and string concatenation with +
private predicate isSource(Expr e) {
  exists(MethodAccess ma | 
    ma.getMethod().getName().matches("format") and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") |
    e = ma
  )
  or
  exists(BinaryExpr be | 
    be.getOp() = BinaryOperator.PLUS and
    e = be
  )
}

// Sources: parameters named $SQL
private predicate isSqlParam(Expr e) {
  exists(Parameter p |
    p.getName() = "$SQL" and
    e = p.getAnAccess()
  )
}

// Sink: executeQuery calls on BasePeer or GroupPeer
private predicate isSink(MethodAccess ma) {
  ma.getMethod().getName() = "executeQuery" and
  (
    ma.getMethod().getDeclaringType().hasQualifiedName("", "BasePeer") or
    ma.getMethod().getDeclaringType().hasQualifiedName("", "GroupPeer")
  ) and
  ma.getArgument(0) = ma.getAnArgument()
}

// Sanitizer: string literals
private predicate isSanitizer(Expr e) {
  exists(StringLiteral sl | e = sl)
}

from Expr source, MethodAccess sink
where
  (isSource(source) or isSqlParam(source)) and
  isSink(sink) and
  not exists(Expr sanitizer | 
    isSanitizer(sanitizer) and
    sanitizer.flowsTo(source)
  ) and
  source.flowsTo(sink.getArgument(0))
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection. Use prepared statements instead."