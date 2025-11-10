/**
 * @name Unencrypted Socket
 * @description Detected use of a Java socket that is not encrypted.
 *              As a result, the traffic could be read by an attacker intercepting the network traffic.
 *              Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory' instead.
 * @id unencrypted-socket
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @tags security
 *       java
 *       external/cwe/cwe-319
 *       external/owasp/a03:2017
 *       external/owasp/a02:2021
 */
import java

from ConstructorCall c
where 
  (c.getConstructedType().hasQualifiedName("java.net", "ServerSocket") or
   c.getConstructedType().hasQualifiedName("java.net", "Socket")) and
  not c.getConstructedType().hasQualifiedName("javax.net.ssl", "SSLSocket") and
  not c.getConstructedType().hasQualifiedName("javax.net.ssl", "SSLServerSocket")
select c, "Use of unencrypted socket. Consider using SSLSocket instead."