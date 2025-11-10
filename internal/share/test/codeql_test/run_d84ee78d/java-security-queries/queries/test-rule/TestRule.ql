/**
 * @name MongoDB NoSQL Injection
 * @description Detected non-constant data passed into a NoSQL query using the 'where' evaluation operator.
 * @kind problem
 * @problem.severity warning
 * @id java/mongodb-nosqli
 * @tags security
 *       external/cwe/cwe-943
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 *       external/nosql
 *       external/mongodb
 */

import java

// Basic pattern of putting $where clause directly
from MethodCall putCall, MethodCall putAllCall, MethodCall appendCall, 
     ConstructorCall basicDBObjectConstructorCall, ConstructorCall basicDBObjectWithMapConstructorCall,
     MethodCall startCall, MethodCall startWithMapCall, MethodCall addCall, 
     MethodCall appendCallOnBuilder
where
  // .put("$where", ...)
  (putCall.getMethod().getName() = "put" and 
   putCall.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObject") and
   exists(putCall.getArgument(0).(StringLiteral).getValue()) and 
   putCall.getArgument(0).(StringLiteral).getValue() = "$where") 
  or
  // .putAll(map) after .put("$where") into map
  (putAllCall.getMethod().getName() = "putAll" and 
   putAllCall.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObject") and
   exists(MethodCall mapPut | 
     mapPut.getMethod().getName() = "put" and
     mapPut.getMethod().getDeclaringType().hasQualifiedName("java.util", "HashMap") and
     exists(mapPut.getArgument(0).(StringLiteral).getValue()) and
     mapPut.getArgument(0).(StringLiteral).getValue() = "$where" and
     mapPut.getQualifier() = putAllCall.getArgument(0)))
  or
  // .append("$where", ...)
  (appendCall.getMethod().getName() = "append" and 
   appendCall.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObject") and
   exists(appendCall.getArgument(0).(StringLiteral).getValue()) and 
   appendCall.getArgument(0).(StringLiteral).getValue() = "$where")
  or
  // new BasicDBObject("$where", ...)
  (basicDBObjectConstructorCall.getConstructor().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObject") and
   exists(basicDBObjectConstructorCall.getArgument(0).(StringLiteral).getValue()) and
   basicDBObjectConstructorCall.getArgument(0).(StringLiteral).getValue() = "$where")
  or
  // new BasicDBObject(map) after .put("$where") into map
  (basicDBObjectWithMapConstructorCall.getConstructor().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObject") and
   exists(MethodCall mapPut |
     mapPut.getMethod().getName() = "put" and
     mapPut.getMethod().getDeclaringType().hasQualifiedName("java.util", "HashMap") and
     exists(mapPut.getArgument(0).(StringLiteral).getValue()) and
     mapPut.getArgument(0).(StringLiteral).getValue() = "$where" and
     mapPut.getQualifier() = basicDBObjectWithMapConstructorCall.getArgument(0)))
  or
  // BasicDBObjectBuilder.start().add("$where", ...)
  (addCall.getMethod().getName() = "add" and 
   addCall.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObjectBuilder") and
   exists(addCall.getArgument(0).(StringLiteral).getValue()) and 
   addCall.getArgument(0).(StringLiteral).getValue() = "$where" and
   addCall.getQualifier() = startCall.getQualifier())
  or
  // BasicDBObjectBuilder.start().append("$where", ...)
  (appendCallOnBuilder.getMethod().getName() = "append" and 
   appendCallOnBuilder.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObjectBuilder") and
   exists(appendCallOnBuilder.getArgument(0).(StringLiteral).getValue()) and 
   appendCallOnBuilder.getArgument(0).(StringLiteral).getValue() = "$where" and
   appendCallOnBuilder.getQualifier() = startCall.getQualifier())
  or
  // BasicDBObjectBuilder.start("$where", ...)
  (startCall.getMethod().getName() = "start" and 
   startCall.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObjectBuilder") and
   exists(startCall.getArgument(0).(StringLiteral).getValue()) and 
   startCall.getArgument(0).(StringLiteral).getValue() = "$where")
  or
  // BasicDBObjectBuilder.start(map) after .put("$where") into map
  (startWithMapCall.getMethod().getName() = "start" and 
   startWithMapCall.getMethod().getDeclaringType().hasQualifiedName("com.mongodb", "BasicDBObjectBuilder") and
   exists(MethodCall mapPut |
     mapPut.getMethod().getName() = "put" and
     mapPut.getMethod().getDeclaringType().hasQualifiedName("java.util", "HashMap") and
     exists(mapPut.getArgument(0).(StringLiteral).getValue()) and
     mapPut.getArgument(0).(StringLiteral).getValue() = "$where" and
     mapPut.getQualifier() = startWithMapCall.getArgument(0)))
select putCall, "Non-constant data passed into a NoSQL query using the 'where' operator. This could lead to NoSQL injection."