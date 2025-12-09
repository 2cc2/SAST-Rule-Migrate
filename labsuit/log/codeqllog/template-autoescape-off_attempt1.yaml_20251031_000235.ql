/**
 * @name Template Autoescape Off
 * @description Detected a segment of a Flask template where autoescaping is explicitly disabled with '{% autoescape off %}'. 
 *              This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is 
 *              a cross-site scripting (XSS) vulnerability, or turn autoescape on.
 * @kind problem
 * @problem.severity warning
 * @id flask/template-autoescape-off
 * @tags security
 *       cwe-79
 *       owasp-a07:2017
 *       owasp-a03:2021
 *       flask
 */

import python

from StringLiteral s
where s.getValue().regexpMatch(".*\{\%\s*autoescape\s+false\s*\%\}.*")
select s, "Found Flask template with autoescape=False, this may lead to XSS vulnerabilities."