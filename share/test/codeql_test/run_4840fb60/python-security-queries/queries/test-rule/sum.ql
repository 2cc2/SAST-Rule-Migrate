/**
 * @name Construction of a cookie using user-supplied input
 * @description Constructing cookies from user input may allow an attacker to perform a Cookie Poisoning attack.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @security-severity 5.0
 * @id py/cookie-injection
 * @tags security
 *       external/cwe/cwe-020
 */

import python
import CookieInjectionFlow::PathGraph
// private import python
// import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources

// private import python
// private import semmle.python.dataflow.new.DataFlow
// Need to import since frameworks can extend `RemoteFlowSource::Range`
// private import semmle.python.Frameworks
// private import semmle.python.Concepts

// If you add modeling of a new framework/library, remember to add it to the docs in
// `docs/codeql/reusables/supported-frameworks.rst`

// private import semmle.python.frameworks.Aioch
// private import semmle.python.frameworks.Aiofile
// private import semmle.python.frameworks.Aiofiles
private import semmle.python.frameworks.Aiohttp

// private import semmle.python.frameworks.Aiomysql
// private import semmle.python.frameworks.Aiopg
// private import semmle.python.frameworks.Aiosqlite
// private import semmle.python.frameworks.Airspeed
// private import semmle.python.frameworks.Anyio

private import semmle.python.frameworks.Bottle
// private import semmle.python.frameworks.BSon
// private import semmle.python.frameworks.CassandraDriver
// private import semmle.python.frameworks.Chameleon
// private import semmle.python.frameworks.Cherrypy
// private import semmle.python.frameworks.Chevron
// private import semmle.python.frameworks.ClickhouseDriver
// private import semmle.python.frameworks.Cryptodome
// private import semmle.python.frameworks.Cryptography
// private import semmle.python.frameworks.Cx_Oracle
// private import semmle.python.frameworks.data.ModelsAsData
// private import semmle.python.frameworks.Dill
private import semmle.python.frameworks.Django
// private import semmle.python.frameworks.Fabric
// private import semmle.python.frameworks.FastApi
private import semmle.python.frameworks.Flask
// private import semmle.python.frameworks.FlaskAdmin
// private import semmle.python.frameworks.FlaskSqlAlchemy
// private import semmle.python.frameworks.Genshi
private import semmle.python.frameworks.Gradio
// private import semmle.python.frameworks.Hdbcli
// private import semmle.python.frameworks.Httpx
// private import semmle.python.frameworks.Idna
// private import semmle.python.frameworks.Invoke
// private import semmle.python.frameworks.Jinja2
// private import semmle.python.frameworks.Jmespath
// private import semmle.python.frameworks.Joblib
// private import semmle.python.frameworks.JsonPickle
// private import semmle.python.frameworks.Ldap
// private import semmle.python.frameworks.Ldap3
// private import semmle.python.frameworks.Libtaxii
// private import semmle.python.frameworks.Libxml2
// private import semmle.python.frameworks.Lxml
// private import semmle.python.frameworks.Mako
// private import semmle.python.frameworks.MarkupSafe
// private import semmle.python.frameworks.Multidict
// private import semmle.python.frameworks.Mysql
// private import semmle.python.frameworks.MySQLdb
// private import semmle.python.frameworks.Numpy
// private import semmle.python.frameworks.Opml
// private import semmle.python.frameworks.Oracledb
// private import semmle.python.frameworks.Pandas
// private import semmle.python.frameworks.Paramiko
// private import semmle.python.frameworks.Peewee
// private import semmle.python.frameworks.Pexpect
// private import semmle.python.frameworks.Phoenixdb
// private import semmle.python.frameworks.Psycopg
// private import semmle.python.frameworks.Psycopg2
// private import semmle.python.frameworks.Pycurl
// private import semmle.python.frameworks.Pydantic
// private import semmle.python.frameworks.PyMongo
// private import semmle.python.frameworks.Pymssql
// private import semmle.python.frameworks.PyMySQL
// private import semmle.python.frameworks.Pyodbc
private import semmle.python.frameworks.Pyramid
// private import semmle.python.frameworks.Requests
private import semmle.python.frameworks.RestFramework
// private import semmle.python.frameworks.Rsa
// private import semmle.python.frameworks.RuamelYaml
// private import semmle.python.frameworks.Sanic
// private import semmle.python.frameworks.ServerLess
// private import semmle.python.frameworks.Setuptools
// private import semmle.python.frameworks.Simplejson
// private import semmle.python.frameworks.SqlAlchemy
// private import semmle.python.frameworks.Starlette
private import semmle.python.frameworks.Stdlib
private import semmle.python.frameworks.Streamlit
// private import semmle.python.frameworks.Toml
// private import semmle.python.frameworks.Torch
private import semmle.python.frameworks.Tornado
// private import semmle.python.frameworks.TRender
private import semmle.python.frameworks.Twisted
// private import semmle.python.frameworks.Ujson
// private import semmle.python.frameworks.Urllib3
// private import semmle.python.frameworks.Xmltodict
// private import semmle.python.frameworks.Yaml
// private import semmle.python.frameworks.Yarl


/**
 * Provides default sources, sinks and sanitizers for detecting
 * "cookie injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module CookieInjection {
  /**
   * A data flow source for "cookie injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "cookie injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "cookie injection" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

//   deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A write to a cookie, considered as a sink.
   */
  class CookieWriteSink extends Sink {
    CookieWriteSink() {
      exists(Http::Server::CookieWrite cw |
        this = [cw.getNameArg(), cw.getValueArg(), cw.getHeaderArg()]
      )
    }
  }
}

/**
 * A taint-tracking configuration for detecting "cookie injection" vulnerabilities.
 */
module CookieInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CookieInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof CookieInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CookieInjection::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "cookie injection" vulnerabilities. */
module CookieInjectionFlow = TaintTracking::Global<CookieInjectionConfig>;



from CookieInjectionFlow::PathNode source, CookieInjectionFlow::PathNode sink
where CookieInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Cookie is constructed from a $@.", source.getNode(),
  "user-supplied input"