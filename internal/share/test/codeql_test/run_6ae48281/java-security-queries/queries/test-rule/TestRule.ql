/**
 * @name Overly Permissive File Permission
 * @description Detected file permissions that are overly permissive (read, write, and execute).
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id java/overly-permissive-file-permission
 * @tags security
 *       external/cwe/cwe-276
 *       owasp-a01
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

predicate isOverlyPermissive(Expr permExpr) {
  exists(MethodAccess ma, string permString |
    ma.getMethod().getName() = "fromString" and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file.attribute", "PosixFilePermissions") and
    permString = ma.getArgument(0).(StringLiteral).getValue() and
    (
      permString.regexpMatch(".*......r..") or    // Others read
      permString.regexpMatch(".*.......w.") or    // Others write
      permString.regexpMatch(".*........x")       // Others execute
    ) and
    DataFlow::localFlow(DataFlow::exprNode(ma), DataFlow::exprNode(permExpr))
  )
}

predicate isOverlyPermissivePermission(Expr perm) {
  exists(MethodAccess add, Expr arg |
    add.getMethod().getName() = "add" and
    add.getMethod().getDeclaringType().hasQualifiedName("java.util", "Set<PosixFilePermission>") and
    (
      arg.toString().matches("%OTHERS_READ%") or
      arg.toString().matches("%OTHERS_WRITE%") or
      arg.toString().matches("%OTHERS_EXECUTE%")
    ) and
    DataFlow::localFlow(DataFlow::exprNode(add.getQualifier()), DataFlow::exprNode(perm))
  )
}

from MethodAccess setPerm, Expr perms
where
  setPerm.getMethod().getName() = "setPosixFilePermissions" and
  setPerm.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
  perms = setPerm.getArgument(1) and
  (
    isOverlyPermissive(perms) or
    isOverlyPermissivePermission(perms)
  )
select setPerm, "Overly permissive file permissions detected, may lead to privilege escalation or information leakage."