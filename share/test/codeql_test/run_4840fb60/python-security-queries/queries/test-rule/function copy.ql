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

// import python
import python
// import semmle.python.Exprs
import semmle.python.dataflow.new.TaintTracking
private import semmle.python.dataflow.new.SensitiveDataSources

private import semmle.python.dataflow.new.DataFlow
private import codeql.threatmodels.ThreatModels
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.FlowSummary
private import semmle.python.frameworks.data.ModelsAsData

class ThreatModelSource extends DataFlow::Node instanceof ThreatModelSource::Range {
  /**
   * Gets a string that represents the source kind with respect to threat modeling.
   *
   * See
   * - https://github.com/github/codeql/blob/main/docs/codeql/reusables/threat-model-description.rst
   * - https://github.com/github/codeql/blob/main/shared/threat-models/ext/threat-model-grouping.model.yml
   */
  string getThreatModel() { result = super.getThreatModel() }

  /** Gets a string that describes the type of this threat-model source. */
  string getSourceType() { result = super.getSourceType() }
}

/** Provides a class for modeling new sources for specific threat-models. */
module ThreatModelSource {
  /**
   * A data flow source, for a specific threat-model.
   *
   * Extend this class to model new APIs. If you want to refine existing API models,
   * extend `ThreatModelSource` instead.
   */
  abstract class Range extends DataFlow::Node {
    /**
     * Gets a string that represents the source kind with respect to threat modeling.
     *
     * See
     * - https://github.com/github/codeql/blob/main/docs/codeql/reusables/threat-model-description.rst
     * - https://github.com/github/codeql/blob/main/shared/threat-models/ext/threat-model-grouping.model.yml
     */
    abstract string getThreatModel();

    /** Gets a string that describes the type of this threat-model source. */
    abstract string getSourceType();
  }
}

/**
 * A data flow source that is enabled in the current threat model configuration.
 */
class ActiveThreatModelSource extends ThreatModelSource {
  ActiveThreatModelSource() {
    exists(string kind |
      currentThreatModel(kind) and
      this.getThreatModel() = kind
    )
  }
}


/**
 * A data flow source of remote user input.
 *
 * Extend this class to refine existing API models. If you want to model new APIs,
 * extend `RemoteFlowSource::Range` instead.
 */
class RemoteFlowSource extends ThreatModelSource instanceof RemoteFlowSource::Range { }

/** Provides a class for modeling new sources of remote user input. */
module RemoteFlowSource {
  /**
   * A data flow source of remote user input.
   *
   * Extend this class to model new APIs. If you want to refine existing API models,
   * extend `RemoteFlowSource` instead.
   */
  abstract class Range extends ThreatModelSource::Range {
    override string getThreatModel() { result = "remote" }
  }
}




/**
 * Provides models for the `flask` PyPI package.
 * See https://flask.palletsprojects.com/en/1.1.x/.
 */
module Flask {
  // /** Gets a reference to the `flask.request` object. */
  API::Node request() {
    result = API::moduleImport(["flask", "flask_restful"]).getMember("request")
    or
    result = sessionInterfaceRequestParam()
  }

  /** Gets a `request` parameter of an implementation of `open_session` in a subclass of `flask.sessions.SessionInterface` */
  private API::Node sessionInterfaceRequestParam() {
    result =
      API::moduleImport("flask")
          .getMember("sessions")
          .getMember("SessionInterface")
          .getASubclass+()
          .getMember("open_session")
          .getParameter(1)
  }

  private class FlaskRequestSource extends RemoteFlowSource::Range {
    FlaskRequestSource() { this = request().asSource() }

    override string getSourceType() { result = "flask.request" }
  }

 
}
module Http {
  /** Gets an HTTP verb, in upper case */
  string httpVerb() { result in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] }

  /** Gets an HTTP verb, in lower case */
  string httpVerbLower() { result = httpVerb().toLowerCase() }

  /** Provides classes for modeling HTTP servers. */
  module Server {
    /**
     * A data-flow node that creates a HTTP response on a server.
     *
     * Note: we don't require that this response must be sent to a client (a kind of
     * "if a tree falls in a forest and nobody hears it" situation).
     *
     * Extend this class to refine existing API models. If you want to model new APIs,
     * extend `HttpResponse::Range` instead.
     */
    class HttpResponse extends DataFlow::Node instanceof HttpResponse::Range {
      /** Gets the data-flow node that specifies the body of this HTTP response. */
      DataFlow::Node getBody() { result = super.getBody() }

      /** Gets the mimetype of this HTTP response, if it can be statically determined. */
      string getMimetype() { result = super.getMimetype() }
    }

    /** Provides a class for modeling new HTTP response APIs. */
    module HttpResponse {
      /**
       * A data-flow node that creates a HTTP response on a server.
       *
       * Note: we don't require that this response must be sent to a client (a kind of
       * "if a tree falls in a forest and nobody hears it" situation).
       *
       * Extend this class to model new APIs. If you want to refine existing API models,
       * extend `HttpResponse` instead.
       */
      abstract class Range extends DataFlow::Node {
        /** Gets the data-flow node that specifies the body of this HTTP response. */
        abstract DataFlow::Node getBody();

        /** Gets the data-flow node that specifies the content-type/mimetype of this HTTP response, if any. */
        abstract DataFlow::Node getMimetypeOrContentTypeArg();

        /** Gets the default mimetype that should be used if `getMimetypeOrContentTypeArg` has no results. */
        abstract string getMimetypeDefault();

        /** Gets the mimetype of this HTTP response, if it can be statically determined. */
        string getMimetype() {
          exists(StringLiteral str |
            this.getMimetypeOrContentTypeArg().getALocalSource() = DataFlow::exprNode(str) and
            result = str.getText().splitAt(";", 0)
          )
          or
          not exists(this.getMimetypeOrContentTypeArg()) and
          result = this.getMimetypeDefault()
        }
      }
    }



    /**
     * A data-flow node that sets a header in an HTTP response.
     *
     * Extend this class to model new APIs. If you want to refine existing API models,
     * extend `ResponseHeaderWrite::Range` instead.
     */
    class ResponseHeaderWrite extends DataFlow::Node instanceof ResponseHeaderWrite::Range {
      /**
       * Gets the argument containing the header name.
       */
      DataFlow::Node getNameArg() { result = super.getNameArg() }

      /**
       * Gets the argument containing the header value.
       */
      DataFlow::Node getValueArg() { result = super.getValueArg() }

      /**
       * Holds if newlines are accepted in the header name argument.
       */
      predicate nameAllowsNewline() { super.nameAllowsNewline() }

      /**
       * Holds if newlines are accepted in the header value argument.
       */
      predicate valueAllowsNewline() { super.valueAllowsNewline() }
    }

    /** Provides a class for modeling header writes on HTTP responses. */
    module ResponseHeaderWrite {
      /**
       *A data-flow node that sets a header in an HTTP response.
       *
       * Extend this class to model new APIs. If you want to refine existing API models,
       * extend `ResponseHeaderWrite` instead.
       */
      abstract class Range extends DataFlow::Node {
        /**
         * Gets the argument containing the header name.
         */
        abstract DataFlow::Node getNameArg();

        /**
         * Gets the argument containing the header value.
         */
        abstract DataFlow::Node getValueArg();

        /**
         * Holds if newlines are accepted in the header name argument.
         */
        abstract predicate nameAllowsNewline();

        /**
         * Holds if newlines are accepted in the header value argument.
         */
        abstract predicate valueAllowsNewline();
      }
    }



 

    /**
     * A data-flow node that sets a cookie in an HTTP response.
     *
     * Extend this class to refine existing API models. If you want to model new APIs,
     * extend `HTTP::CookieWrite::Range` instead.
     */
    class CookieWrite extends DataFlow::Node instanceof CookieWrite::Range {
      /**
       * Gets the argument, if any, specifying the raw cookie header.
       */
      DataFlow::Node getHeaderArg() { result = super.getHeaderArg() }

      /**
       * Gets the argument, if any, specifying the cookie name.
       */
      DataFlow::Node getNameArg() { result = super.getNameArg() }

      /**
       * Gets the argument, if any, specifying the cookie value.
       */
      DataFlow::Node getValueArg() { result = super.getValueArg() }

      /** Holds if the name of this cookie indicates it may contain sensitive information. */
      predicate isSensitive() {
        exists(DataFlow::Node name |
          name = [this.getNameArg(), this.getHeaderArg()] and
          (
            DataFlow::localFlow(any(SensitiveDataSource src), name)
            or
            name = sensitiveLookupStringConst(_)
          )
        )
      }

      /**
       * Holds if the `Secure` flag of the cookie is known to have a value of `b`.
       */
      predicate hasSecureFlag(boolean b) { super.hasSecureFlag(b) }

      /**
       * Holds if the `HttpOnly` flag of the cookie is known to have a value of `b`.
       */
      predicate hasHttpOnlyFlag(boolean b) { super.hasHttpOnlyFlag(b) }

      /**
       * Holds if the `SameSite` attribute of the cookie is known to have a value of `v`.
       */
      predicate hasSameSiteAttribute(CookieWrite::SameSiteValue v) { super.hasSameSiteAttribute(v) }
    }

    /**
     * A dataflow call node to a method that sets a cookie in an http response,
     * and has common keyword arguments `secure`, `httponly`, and `samesite` to set the attributes of the cookie.
     *
     * See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
     */
    abstract class SetCookieCall extends CookieWrite::Range, DataFlow::CallCfgNode {
      override predicate hasSecureFlag(boolean b) {
        super.hasSecureFlag(b)
        or
        exists(DataFlow::Node arg, BooleanLiteral bool | arg = this.getArgByName("secure") |
          DataFlow::localFlow(DataFlow::exprNode(bool), arg) and
          b = bool.booleanValue()
        )
        or
        not exists(this.getArgByName("secure")) and
        not exists(this.getKwargs()) and
        b = false
      }

      override predicate hasHttpOnlyFlag(boolean b) {
        super.hasHttpOnlyFlag(b)
        or
        exists(DataFlow::Node arg, BooleanLiteral bool | arg = this.getArgByName("httponly") |
          DataFlow::localFlow(DataFlow::exprNode(bool), arg) and
          b = bool.booleanValue()
        )
        or
        not exists(this.getArgByName("httponly")) and
        not exists(this.getKwargs()) and
        b = false
      }

      override predicate hasSameSiteAttribute(CookieWrite::SameSiteValue v) {
        super.hasSameSiteAttribute(v)
        or
        exists(DataFlow::Node arg, StringLiteral str | arg = this.getArgByName("samesite") |
          DataFlow::localFlow(DataFlow::exprNode(str), arg) and
          (
            str.getText().toLowerCase() = "strict" and
            v instanceof CookieWrite::SameSiteStrict
            or
            str.getText().toLowerCase() = "lax" and
            v instanceof CookieWrite::SameSiteLax
            or
            str.getText().toLowerCase() = "none" and
            v instanceof CookieWrite::SameSiteNone
          )
        )
        or
        not exists(this.getArgByName("samesite")) and
        not exists(this.getKwargs()) and
        v instanceof CookieWrite::SameSiteLax // Lax is the default
      }
    }

    /** Provides a class for modeling new cookie writes on HTTP responses. */
    module CookieWrite {
      /**
       * A data-flow node that sets a cookie in an HTTP response.
       *
       * Note: we don't require that this redirect must be sent to a client (a kind of
       * "if a tree falls in a forest and nobody hears it" situation).
       *
       * Extend this class to model new APIs. If you want to refine existing API models,
       * extend `HttpResponse` instead.
       */
      abstract class Range extends DataFlow::Node {
        /**
         * Gets the argument, if any, specifying the raw cookie header.
         */
        abstract DataFlow::Node getHeaderArg();

        /**
         * Gets the argument, if any, specifying the cookie name.
         */
        abstract DataFlow::Node getNameArg();

        /**
         * Gets the argument, if any, specifying the cookie value.
         */
        abstract DataFlow::Node getValueArg();

        /**
         * Holds if the `Secure` flag of the cookie is known to have a value of `b`.
         */
        predicate hasSecureFlag(boolean b) {
          exists(StringLiteral sl |
            // `sl` is likely a substring of the header
            TaintTracking::localTaint(DataFlow::exprNode(sl), this.getHeaderArg()) and
            sl.getText().regexpMatch("(?i).*;\\s*secure(;.*|\\s*)") and
            b = true
            or
            // `sl` is the entire header
            DataFlow::localFlow(DataFlow::exprNode(sl), this.getHeaderArg()) and
            not sl.getText().regexpMatch("(?i).*;\\s*secure(;.*|\\s*)") and
            b = false
          )
        }

        /**
         * Holds if the `HttpOnly` flag of the cookie is known to have a value of `b`.
         */
        predicate hasHttpOnlyFlag(boolean b) {
          exists(StringLiteral sl |
            // `sl` is likely a substring of the header
            TaintTracking::localTaint(DataFlow::exprNode(sl), this.getHeaderArg()) and
            sl.getText().regexpMatch("(?i).*;\\s*httponly(;.*|\\s*)") and
            b = true
            or
            // `sl` is the entire header
            DataFlow::localFlow(DataFlow::exprNode(sl), this.getHeaderArg()) and
            not sl.getText().regexpMatch("(?i).*;\\s*httponly(;.*|\\s*)") and
            b = false
          )
        }

        /**
         * Holds if the `SameSite` flag of the cookie is known to have a value of `v`.
         */
        predicate hasSameSiteAttribute(SameSiteValue v) {
          exists(StringLiteral sl |
            // `sl` is likely a substring of the header
            TaintTracking::localTaint(DataFlow::exprNode(sl), this.getHeaderArg()) and
            (
              sl.getText().regexpMatch("(?i).*;\\s*samesite=strict(;.*|\\s*)") and
              v instanceof SameSiteStrict
              or
              sl.getText().regexpMatch("(?i).*;\\s*samesite=lax(;.*|\\s*)") and
              v instanceof SameSiteLax
              or
              sl.getText().regexpMatch("(?i).*;\\s*samesite=none(;.*|\\s*)") and
              v instanceof SameSiteNone
            )
            or
            // `sl` is the entire header
            DataFlow::localFlow(DataFlow::exprNode(sl), this.getHeaderArg()) and
            not sl.getText().regexpMatch("(?i).*;\\s*samesite=(strict|lax|none)(;.*|\\s*)") and
            v instanceof SameSiteLax // Lax is the default
          )
        }
      }

      private newtype TSameSiteValue =
        TSameSiteStrict() or
        TSameSiteLax() or
        TSameSiteNone()

      /** A possible value for the SameSite attribute of a cookie. */
      class SameSiteValue extends TSameSiteValue {
        /** Gets a string representation of this value. */
        string toString() { none() }
      }

      /** A `Strict` value of the `SameSite` attribute. */
      class SameSiteStrict extends SameSiteValue, TSameSiteStrict {
        override string toString() { result = "Strict" }
      }

      /** A `Lax` value of the `SameSite` attribute. */
      class SameSiteLax extends SameSiteValue, TSameSiteLax {
        override string toString() { result = "Lax" }
      }

      /** A `None` value of the `SameSite` attribute. */
      class SameSiteNone extends SameSiteValue, TSameSiteNone {
        override string toString() { result = "None" }
      }
    }

    /** A write to a `Set-Cookie` header that sets a cookie directly. */
    private class CookieHeaderWrite extends CookieWrite::Range instanceof Http::Server::ResponseHeaderWrite
    {
      CookieHeaderWrite() {
        exists(StringLiteral str |
          str.getText().toLowerCase() = "set-cookie" and
          DataFlow::exprNode(str)
              .(DataFlow::LocalSourceNode)
              .flowsTo(this.(Http::Server::ResponseHeaderWrite).getNameArg())
        )
      }

      override DataFlow::Node getNameArg() { none() }

      override DataFlow::Node getHeaderArg() {
        result = this.(Http::Server::ResponseHeaderWrite).getValueArg()
      }

      override DataFlow::Node getValueArg() { none() }
    }

 

  }

}
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