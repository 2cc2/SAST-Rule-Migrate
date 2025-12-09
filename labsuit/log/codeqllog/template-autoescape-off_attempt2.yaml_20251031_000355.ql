/**
 * @name Flask template autoescape off detection
 * @description Detects Flask templates where autoescape is explicitly disabled.
 * @kind problem
 * @problem.severity warning
 * @id python/flask/template-autoescape-off
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07
 *       external/owasp/a03
 *       technology/flask
 * @precision medium
 */

import python

from StringLiteral s
where s.matches(".*\\{\\%\\s*autoescape\\s+false\\s*\\%\\}.*")
select s, "Detected a segment of a Flask template where autoescaping is explicitly disabled with '{% autoescape off %}'. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability, or turn autoescape on."