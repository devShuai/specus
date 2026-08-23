(function () {
  try {
    var currentScript = document.currentScript;
    var P = currentScript && currentScript.getAttribute("data-specus-prefix");
    if (!P) return;

    function hrefOf(value) {
      if (typeof value === "string") return value;
      if (value && typeof value.href === "string") return value.href;
      if (value && typeof value.url === "string") return value.url;
      return "";
    }

    function locationParts() {
      if (typeof location === "undefined") return null;
      return {
        http: location.origin,
        ws: (location.protocol === "https:" ? "wss://" : "ws://") + location.host,
      };
    }

    // An absolute same-origin URL may contain a path built as origin + "/" + "/path".
    // A bare //host/path remains a protocol-relative URL and must not be rewritten.
    function normalizePath(path, base) {
      if (path.length > 1 && path.charAt(1) === "/") {
        if (!base) return null;
        while (path.length > 1 && path.charAt(1) === "/") path = path.slice(1);
      }
      return path;
    }

    function localUrlParts(value) {
      if (typeof value !== "string" || !value) return false;
      var path = value;
      var parts = locationParts();
      var base = "";
      if (value.charAt(0) !== "/") {
        if (!parts) return null;
        if (value.indexOf(parts.http) === 0) base = parts.http;
        else if (value.indexOf(parts.ws) === 0) base = parts.ws;
        else return null;
        path = value.slice(base.length);
        if (!path || path.charAt(0) !== "/") return null;
      }
      path = normalizePath(path, base);
      return path ? { base: base, path: path } : null;
    }

    function hasTunnelPrefix(path) {
      return (
        path.indexOf(P + "/") === 0 ||
        path === P ||
        path.indexOf(P + "?") === 0 ||
        path.indexOf(P + "#") === 0
      );
    }

    function encodeRawQueryBraces(value) {
      var queryStart = value.indexOf("?");
      var fragmentStart = value.indexOf("#");
      if (queryStart < 0 || (fragmentStart >= 0 && queryStart > fragmentStart)) return value;
      var queryEnd = fragmentStart < 0 ? value.length : fragmentStart;
      var query = value.slice(queryStart + 1, queryEnd);
      if (query.indexOf("{") < 0 && query.indexOf("}") < 0) return value;
      query = query.replace(/{/g, "%7B").replace(/}/g, "%7D");
      return value.slice(0, queryStart + 1) + query + value.slice(queryEnd);
    }

    function rewriteUrl(value) {
      var local = localUrlParts(value);
      if (!local) return value;
      var rewritten = hasTunnelPrefix(local.path)
        ? value
        : local.base + P + local.path;
      return encodeRawQueryBraces(rewritten);
    }

    function rewriteInput(input) {
      var href = hrefOf(input);
      if (!href) return input;
      var rewritten = rewriteUrl(href);
      if (rewritten === href) return input;
      if (typeof Request === "function" && input instanceof Request) {
        return new Request(rewritten, input);
      }
      return rewritten;
    }

    var urlAttributes = {
      src: 1,
      href: 1,
      action: 1,
      formaction: 1,
      poster: 1,
      background: 1,
      data: 1,
      cite: 1,
      longdesc: 1,
      usemap: 1,
      "data-src": 1,
      "data-href": 1,
    };
    var observedUrlAttributes = [
      "src",
      "href",
      "action",
      "formaction",
      "poster",
      "background",
      "data",
      "cite",
      "longdesc",
      "usemap",
      "data-src",
      "data-href",
      "srcset",
      "style",
    ];
    var observedUrlSelector = observedUrlAttributes
      .map(function (name) {
        return "[" + name + "]";
      })
      .concat(["style"])
      .join(",");

    function rewriteSrcset(value) {
      if (typeof value !== "string") return value;
      return value.replace(
        /(^|,\s*)((?:https?:)?\/\/[^\s,]+|\/[^\s,]+)/gi,
        function (match, separator, url) {
          return separator + rewriteUrl(url);
        },
      );
    }

    function rewriteCssUrls(value) {
      if (typeof value !== "string" || value.toLowerCase().indexOf("url(") < 0) {
        return value;
      }
      return value.replace(
        /url\(\s*(?:(["'])([\s\S]*?)\1|([^)]*?))\s*\)/gi,
        function (match, quote, quotedUrl, unquotedUrl) {
          var url = quote ? quotedUrl : String(unquotedUrl || "").trim();
          var rewritten = rewriteUrl(url);
          if (rewritten === url) return match;
          return "url(" + (quote || "") + rewritten + (quote || "") + ")";
        },
      );
    }

    function rewriteAttributeValue(name, value) {
      if (typeof value !== "string") return value;
      var normalizedName = String(name || "").toLowerCase();
      if (normalizedName === "style") return rewriteCssUrls(value);
      if (normalizedName === "srcset") return rewriteSrcset(value);
      return urlAttributes[normalizedName] ? rewriteUrl(value) : value;
    }

    function rewriteHtmlMarkup(value) {
      if (typeof value !== "string" || value.indexOf("/") < 0) return value;
      var rewritten = value.replace(
        /(\bstyle\s*=\s*)(["'])([\s\S]*?)\2/gi,
        function (match, prefix, quote, css) {
          return prefix + quote + rewriteCssUrls(css) + quote;
        },
      );
      rewritten = rewritten.replace(
        /(\b(?:data-src|data-href|formaction|background|longdesc|poster|action|srcset|usemap|cite|href|src|data)\s*=\s*)(["'])([\s\S]*?)\2/gi,
        function (match, prefix, quote, url) {
          var nameMatch = /^\s*([^\s=]+)/.exec(prefix);
          return prefix + quote
            + rewriteAttributeValue(nameMatch ? nameMatch[1] : "", url)
            + quote;
        },
      );
      return rewritten.replace(
        /(\b(?:data-src|data-href|formaction|background|longdesc|poster|action|srcset|usemap|cite|href|src|data)\s*=\s*)([^\s"'=<>]+)/gi,
        function (match, prefix, url) {
          var nameMatch = /^\s*([^\s=]+)/.exec(prefix);
          return prefix + rewriteAttributeValue(nameMatch ? nameMatch[1] : "", url);
        },
      );
    }

    function rewriteElementAttributes(element) {
      if (!element || typeof element.getAttribute !== "function") return;
      for (var index = 0; index < observedUrlAttributes.length; index += 1) {
        var name = observedUrlAttributes[index];
        var value = element.getAttribute(name);
        if (value === null) continue;
        var rewritten = rewriteAttributeValue(name, value);
        if (rewritten !== value) {
          if (typeof originalSetAttribute === "function") {
            originalSetAttribute.call(element, name, rewritten);
          } else {
            element.setAttribute(name, rewritten);
          }
        }
      }
    }

    function rewriteStyleElement(element) {
      if (
        !element ||
        String(element.nodeName || "").toLowerCase() !== "style" ||
        typeof element.textContent !== "string"
      ) {
        return;
      }
      var rewritten = rewriteCssUrls(element.textContent);
      if (rewritten !== element.textContent) element.textContent = rewritten;
    }

    function rewriteNodeTree(node) {
      if (!node) return;
      if (node.nodeType === 1) {
        rewriteElementAttributes(node);
        rewriteStyleElement(node);
      }
      if (typeof node.querySelectorAll !== "function") return;
      var elements = node.querySelectorAll(observedUrlSelector);
      for (var index = 0; index < elements.length; index += 1) {
        rewriteElementAttributes(elements[index]);
        rewriteStyleElement(elements[index]);
      }
    }

    if (typeof fetch === "function") {
      var originalFetch = fetch;
      window.fetch = function (input, init) {
        try {
          input = rewriteInput(input);
        } catch (ignored) {}
        return originalFetch.call(this, input, init);
      };
    }

    if (typeof XMLHttpRequest !== "undefined") {
      var originalOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url) {
        try {
          var href = hrefOf(url);
          if (href) url = rewriteUrl(href);
        } catch (ignored) {}
        arguments[1] = url;
        return originalOpen.apply(this, arguments);
      };
    }

    function wrapHistory(name) {
      var original = history[name];
      if (typeof original === "function") {
        history[name] = function (state, title, url) {
          try {
            if (typeof url === "string") url = rewriteUrl(url);
          } catch (ignored) {}
          return original.call(this, state, title, url);
        };
      }
    }

    if (typeof history !== "undefined") {
      wrapHistory("pushState");
      wrapHistory("replaceState");
    }

    if (typeof Element !== "undefined") {
      var originalSetAttribute = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function (name, value) {
        try {
          if (name && typeof value === "string") {
            value = rewriteAttributeValue(name, value);
          }
        } catch (ignored) {}
        return originalSetAttribute.call(this, name, value);
      };

      var originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
      if (typeof originalInsertAdjacentHTML === "function") {
        Element.prototype.insertAdjacentHTML = function (position, text) {
          try {
            text = rewriteHtmlMarkup(text);
          } catch (ignored) {}
          return originalInsertAdjacentHTML.call(this, position, text);
        };
      }
    }

    function rewriteInsertedNode(parent, node) {
      try {
        if (
          parent &&
          String(parent.nodeName || "").toLowerCase() === "style" &&
          node &&
          node.nodeType === 3 &&
          typeof node.nodeValue === "string"
        ) {
          var rewrittenNodeValue = rewriteCssUrls(node.nodeValue);
          if (rewrittenNodeValue !== node.nodeValue) {
            node.nodeValue = rewrittenNodeValue;
          }
        }
        rewriteNodeTree(node);
      } catch (ignored) {}
    }

    if (typeof Node !== "undefined") {
      var originalAppendChild = Node.prototype.appendChild;
      if (typeof originalAppendChild === "function") {
        Node.prototype.appendChild = function (newChild) {
          rewriteInsertedNode(this, newChild);
          return originalAppendChild.call(this, newChild);
        };
      }
      var originalInsertBefore = Node.prototype.insertBefore;
      if (typeof originalInsertBefore === "function") {
        Node.prototype.insertBefore = function (newChild, referenceChild) {
          rewriteInsertedNode(this, newChild);
          return originalInsertBefore.call(this, newChild, referenceChild);
        };
      }
      var originalReplaceChild = Node.prototype.replaceChild;
      if (typeof originalReplaceChild === "function") {
        Node.prototype.replaceChild = function (newChild, oldChild) {
          rewriteInsertedNode(this, newChild);
          return originalReplaceChild.call(this, newChild, oldChild);
        };
      }
    }

    function wrapAttribute(className, property, transformer) {
      var Constructor = window[className];
      if (typeof Constructor !== "function" || !Constructor.prototype) return;
      var prototype = Constructor.prototype;
      var owner = prototype;
      var descriptor;
      while (owner && !(descriptor = Object.getOwnPropertyDescriptor(owner, property))) {
        owner = Object.getPrototypeOf(owner);
      }
      if (!descriptor || typeof descriptor.set !== "function") return;
      var replacement = {
        configurable: true,
        enumerable: descriptor.enumerable,
        set: function (value) {
          try {
            if (typeof value === "string") {
              value = (transformer || rewriteUrl)(value);
            }
          } catch (ignored) {}
          descriptor.set.call(this, value);
        },
      };
      if (descriptor.get) {
        replacement.get = function () {
          return descriptor.get.call(this);
        };
      }
      try {
        Object.defineProperty(prototype, property, replacement);
      } catch (ignored) {
        // Some embedded browsers expose non-configurable DOM descriptors. Keep
        // installing the remaining wrappers instead of disabling the runtime.
      }
    }

    var styleProxyCache =
      typeof WeakMap === "function" ? new WeakMap() : null;

    function wrapStyleAccessor(className) {
      var Constructor = window[className];
      if (
        typeof Constructor !== "function" ||
        !Constructor.prototype ||
        typeof Proxy !== "function"
      ) {
        return;
      }
      var prototype = Constructor.prototype;
      var owner = prototype;
      var descriptor;
      while (owner && !(descriptor = Object.getOwnPropertyDescriptor(owner, "style"))) {
        owner = Object.getPrototypeOf(owner);
      }
      if (!descriptor || typeof descriptor.get !== "function") return;
      var replacement = {
        configurable: true,
        enumerable: descriptor.enumerable,
        get: function () {
          var style = descriptor.get.call(this);
          if (!style || !styleProxyCache) return style;
          var cached = styleProxyCache.get(style);
          if (cached) return cached;
          var proxy = new Proxy(style, {
            get: function (target, property) {
              var value = Reflect.get(target, property, target);
              return typeof value === "function" ? value.bind(target) : value;
            },
            set: function (target, property, value) {
              try {
                if (typeof value === "string") value = rewriteCssUrls(value);
              } catch (ignored) {}
              return Reflect.set(target, property, value, target);
            },
          });
          styleProxyCache.set(style, proxy);
          return proxy;
        },
      };
      if (descriptor.set) {
        replacement.set = function (value) {
          descriptor.set.call(this, value);
        };
      }
      try {
        Object.defineProperty(prototype, "style", replacement);
      } catch (ignored) {}
    }

    wrapAttribute("Element", "innerHTML", rewriteHtmlMarkup);
    wrapAttribute("Element", "outerHTML", rewriteHtmlMarkup);
    wrapAttribute("HTMLStyleElement", "innerHTML", rewriteCssUrls);
    wrapStyleAccessor("HTMLElement");
    wrapStyleAccessor("SVGElement");

    var sourceElements = [
      "HTMLScriptElement",
      "HTMLImageElement",
      "HTMLIFrameElement",
      "HTMLSourceElement",
      "HTMLVideoElement",
      "HTMLAudioElement",
      "HTMLEmbedElement",
      "HTMLInputElement",
      "HTMLMediaElement",
    ];
    for (var sourceIndex = 0; sourceIndex < sourceElements.length; sourceIndex += 1) {
      wrapAttribute(sourceElements[sourceIndex], "src");
      wrapAttribute(sourceElements[sourceIndex], "srcset", rewriteSrcset);
      wrapAttribute(sourceElements[sourceIndex], "poster");
    }
    var hrefElements = [
      "HTMLLinkElement",
      "HTMLAnchorElement",
      "HTMLBaseElement",
      "SVGAElement",
      "SVGImageElement",
    ];
    for (var hrefIndex = 0; hrefIndex < hrefElements.length; hrefIndex += 1) {
      wrapAttribute(hrefElements[hrefIndex], "href");
    }
    wrapAttribute("HTMLFormElement", "action");
    wrapAttribute("HTMLObjectElement", "data");

    if (typeof CSSStyleDeclaration !== "undefined") {
      var originalSetProperty = CSSStyleDeclaration.prototype.setProperty;
      if (typeof originalSetProperty === "function") {
        CSSStyleDeclaration.prototype.setProperty = function (name, value, priority) {
          try {
            value = rewriteCssUrls(value);
          } catch (ignored) {}
          return originalSetProperty.call(this, name, value, priority);
        };
      }
      var cssUrlProperties = [
        "background",
        "backgroundImage",
        "borderImage",
        "borderImageSource",
        "content",
        "cssText",
        "cursor",
        "listStyle",
        "listStyleImage",
        "mask",
        "maskImage",
      ];
      for (var cssIndex = 0; cssIndex < cssUrlProperties.length; cssIndex += 1) {
        wrapAttribute("CSSStyleDeclaration", cssUrlProperties[cssIndex], rewriteCssUrls);
      }
    }

    if (typeof CSSStyleSheet !== "undefined") {
      var originalInsertRule = CSSStyleSheet.prototype.insertRule;
      if (typeof originalInsertRule === "function") {
        CSSStyleSheet.prototype.insertRule = function (rule, index) {
          try {
            rule = rewriteCssUrls(rule);
          } catch (ignored) {}
          return originalInsertRule.call(this, rule, index);
        };
      }
      var originalAddRule = CSSStyleSheet.prototype.addRule;
      if (typeof originalAddRule === "function") {
        CSSStyleSheet.prototype.addRule = function (selector, style, index) {
          try {
            style = rewriteCssUrls(style);
          } catch (ignored) {}
          return originalAddRule.call(this, selector, style, index);
        };
      }
      var originalReplaceSync = CSSStyleSheet.prototype.replaceSync;
      if (typeof originalReplaceSync === "function") {
        CSSStyleSheet.prototype.replaceSync = function (text) {
          try {
            text = rewriteCssUrls(text);
          } catch (ignored) {}
          return originalReplaceSync.call(this, text);
        };
      }
      var originalReplace = CSSStyleSheet.prototype.replace;
      if (typeof originalReplace === "function") {
        CSSStyleSheet.prototype.replace = function (text) {
          try {
            text = rewriteCssUrls(text);
          } catch (ignored) {}
          return originalReplace.call(this, text);
        };
      }
    }

    if (typeof MutationObserver === "function" && typeof document !== "undefined") {
      var urlObserver = new MutationObserver(function (records) {
        for (var recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
          var record = records[recordIndex];
          try {
            if (record.type === "attributes") {
              rewriteElementAttributes(record.target);
            } else if (record.type === "characterData") {
              rewriteInsertedNode(record.target.parentNode, record.target);
            } else if (record.type === "childList") {
              for (var nodeIndex = 0; nodeIndex < record.addedNodes.length; nodeIndex += 1) {
                rewriteInsertedNode(record.target, record.addedNodes[nodeIndex]);
              }
            }
          } catch (ignored) {}
        }
      });
      try {
        urlObserver.observe(document, {
          attributes: true,
          attributeFilter: observedUrlAttributes,
          characterData: true,
          childList: true,
          subtree: true,
        });
      } catch (ignored) {}
    }

    if (typeof EventSource === "function") {
      var OriginalEventSource = EventSource;
      window.EventSource = function (url, configuration) {
        try {
          var href = hrefOf(url);
          if (href) url = rewriteUrl(href);
        } catch (ignored) {}
        return new OriginalEventSource(url, configuration);
      };
      window.EventSource.prototype = OriginalEventSource.prototype;
    }

    if (typeof WebSocket === "function") {
      var OriginalWebSocket = WebSocket;
      window.WebSocket = function (url, protocols) {
        try {
          var href = hrefOf(url);
          if (href) url = rewriteUrl(href);
        } catch (ignored) {}
        return protocols === undefined
          ? new OriginalWebSocket(url)
          : new OriginalWebSocket(url, protocols);
      };
      window.WebSocket.prototype = OriginalWebSocket.prototype;
    }
  } catch (error) {
    if (typeof console !== "undefined" && console && console.warn) {
      console.warn("specus polyfill failed", error);
    }
  }
})();
