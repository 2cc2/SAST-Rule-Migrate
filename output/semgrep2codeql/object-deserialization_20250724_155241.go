/**
 * @name Object deserialization
 * @description Detects object deserialization using ObjectInputStream which is potentially dangerous.
 * @kind problem
 * @problem.severity warning
 * @id java/object-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       external/owasp/a08:2017
 *       external/owasp/a08:2021
 *       cwe2022-top25
 *       cwe2021-top25
 */
import java

from ConstructorCall call
where call.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream")
select call, "Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object."