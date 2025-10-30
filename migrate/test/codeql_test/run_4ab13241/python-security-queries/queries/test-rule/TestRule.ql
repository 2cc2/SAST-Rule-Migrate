/**
 * @name Direct Use of Jinja2
 * @description Detects direct use of jinja2 that may bypass HTML escaping and lead to XSS vulnerabilities
 * @kind taint
 * @problem.severity warning
 * @id python/direct-use-of-jinja2
 */

import python
import semmle.python.security.TaintTracking
import semmle.python.Concepts

class Jinja2EnvironmentCall extends DataFlow::CallNode {
  Jinja2EnvironmentCall() {
    this.getTarget().hasQualifiedName("jinja2", "Environment")
  }
}

class Jinja2TemplateRenderCall extends DataFlow::CallNode {
  Jinja2TemplateRenderCall() {
    // Match jinja2.Template.render() calls
    this.getTarget().hasQualifiedName("jinja2", "Template", "render") or
    // Match any Template.render() calls through regex
    this.getTarget().toString().regexpMatch(".*\\.Template\\.render")
  }
}

class FlaskRenderTemplateCall extends DataFlow::CallNode {
  FlaskRenderTemplateCall() {
    this.getTarget().hasQualifiedName("flask", "render_template")
  }
}

class Jinja2Configuration extends TaintTracking::Configuration {
  Jinja2Configuration() { this = "Jinja2UsageConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof Jinja2EnvironmentCall or
    source instanceof Jinja2TemplateRenderCall
  }

  override predicate isSink(DataFlow::Node sink) { any() }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() = any(FlaskRenderTemplateCall f).getACall()
  }
}

from Jinja2Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected direct use of jinja2. If not done properly, this may bypass HTML escaping which opens up the application to cross-site scripting (XSS) vulnerabilities. Prefer using the Flask method 'render_template()' and templates with a '.html' extension in order to prevent XSS."