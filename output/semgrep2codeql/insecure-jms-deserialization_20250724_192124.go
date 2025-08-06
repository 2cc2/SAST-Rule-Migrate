/**
 * @name Insecure JMS Deserialization
 * @description JMS Object messages depend on Java Serialization for marshalling/unmarshalling
 *     of the message payload when ObjectMessage.getObject() is called.
 *     Deserialization of untrusted data can lead to security flaws; a remote attacker
 *     could via a crafted JMS ObjectMessage to execute
 *     arbitrary code with the permissions of the application listening/consuming JMS Messages.
 *     In this case, the JMS MessageListener consume an ObjectMessage type received inside
 *     the onMessage method, which may lead to arbitrary code execution when calling
 *     the getObject method.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.8
 * @precision medium
 * @id java/insecure-jms-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       external/owasp/a08:2017
 *       external/owasp/a08:2021
 *       external/cwe/top-25-2021
 *       external/cwe/top-25-2022
 */
import java

from MethodAccess getObjectCall, Method onMessage, Class jmsListener
where
  // Match JMS listener class implementing MessageListener
  jmsListener instanceof Type and
  jmsListener.getASupertype*().hasQualifiedName("javax.jms", "MessageListener") and
  
  // Match onMessage method implementation
  onMessage.getName() = "onMessage" and
  onMessage.getDeclaringType() = jmsListener and
  
  // Match getObject() calls within onMessage method
  getObjectCall.getMethod().hasQualifiedName("javax.jms", "ObjectMessage", "getObject") and
  getObjectCall.getEnclosingCallable() = onMessage
select getObjectCall, "Insecure JMS deserialization detected. Deserializing untrusted data via ObjectMessage.getObject() can lead to remote code execution."