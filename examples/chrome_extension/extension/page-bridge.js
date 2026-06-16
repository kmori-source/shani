/**
 * Shani Chrome Extension — Page Bridge (MAIN world)
 *
 * Injected at document_start + world:"MAIN", monkey-patching the browser APIs
 * used by Claude in Chrome to route them through Shani governance.
 *
 * Since chrome.runtime is not available in the MAIN world,
 * window.postMessage is used to communicate with content.js in the ISOLATED world.
 */

(function () {
  "use strict";

  // ── Utilities ─────────────────────────────────────────────────────────────

  let _reqCounter = 0;
  function nextId() {
    return "pb-" + Date.now() + "-" + ++_reqCounter;
  }

  // Deduplicate requests for the same action:target.
  // key: "action:target" → { requestId, callbacks[] }
  const _inflightRequests = new Map();

  /**
   * Ask content.js for approval and receive the result via callback.
   * If the same action+target is already waiting for HITL, the callback is
   * queued and no new request is sent (deduplication).
   * @param {object} payload  - request info including action / target etc.
   * @param {function} cb     - calls cb(approved: boolean)
   */
  function askShani(payload, cb) {
    // scrape / browser_fetch are deduplicated at the hostname level.
    // Even if ad scripts send large numbers of requests to the same domain,
    // only the first one is sent to Shani; the rest follow the same decision.
    let dedupKey;
    if (payload.action === "scrape" || payload.action === "browser_fetch") {
      try {
        const host = new URL(payload.target || "", location.href).hostname;
        dedupKey = payload.action + ":host:" + host;
      } catch {
        dedupKey = payload.action + ":" + (payload.target || "");
      }
    } else {
      dedupKey = payload.action + ":" + (payload.target || "");
    }

    if (_inflightRequests.has(dedupKey)) {
      _inflightRequests.get(dedupKey).callbacks.push(cb);
      return;
    }

    const requestId = nextId();
    _inflightRequests.set(dedupKey, { requestId, callbacks: [cb] });

    function onResponse(event) {
      if (
        event.source !== window ||
        !event.data ||
        event.data.type !== "shani:response" ||
        event.data.requestId !== requestId
      ) {
        return;
      }
      window.removeEventListener("message", onResponse);
      const result = event.data.result || {};
      const approved = result.approved === true;

      const entry = _inflightRequests.get(dedupKey);
      _inflightRequests.delete(dedupKey);
      if (entry) entry.callbacks.forEach((fn) => fn(approved));
    }

    window.addEventListener("message", onResponse);
    window.postMessage({ type: "shani:request", requestId, ...payload }, "*");
  }

  // ── Known ad, analytics, and tracking domains ─────────────────────────────
  // These are external requests made in large numbers by ad scripts,
  // not intentional actions by Claude, so governance is skipped.
  const _PASSTHROUGH_HOST_SUFFIXES = [
    ".googlesyndication.com",
    ".doubleclick.net",
    ".google-analytics.com",
    ".googletagmanager.com",
    ".googletagservices.com",
    ".googleadservices.com",
    ".adsystem.com",
    ".yjtag.yahoo.co.jp",
    ".yads.yahoo.co.jp",
    ".adnxs.com",
    ".rubiconproject.com",
    ".pubmatic.com",
    ".openx.net",
    ".33across.com",
    ".criteo.com",
    ".casalemedia.com",
    ".moatads.com",
    ".rlcdn.com",
    ".turn.com",
    ".tapad.com",
    ".bidswitch.net",
    ".smartadserver.com",
    ".serving-sys.com",
    ".adscale.de",
    ".2mdn.net",
    ".yimg.com",
  ];

  // ── Save all original functions and descriptors upfront ──────────────────
  // Capture before patching so subsequent patches don't interfere with each other.

  const _origOpen         = window.open.bind(window);
  const _origSubmit       = HTMLFormElement.prototype.submit;
  const _origReqSubmit    = HTMLFormElement.prototype.requestSubmit || null;
  const _origPushState    = history.pushState.bind(history);
  const _origReplaceState = history.replaceState.bind(history);
  const _origAssign       = Location.prototype.assign;   // unbound — call with .call(loc, url)
  const _origReplace      = Location.prototype.replace;  // unbound
  const _hrefDesc         = Object.getOwnPropertyDescriptor(Location.prototype, "href");
  const _origFetch        = window.fetch.bind(window);
  const _origXHROpen      = XMLHttpRequest.prototype.open;
  const _origXHRSend      = XMLHttpRequest.prototype.send;

  // ── window.open ───────────────────────────────────────────────────────────

  window.open = function (url, target, features) {
    askShani({ action: "navigate", target: String(url || "") }, (approved) => {
      if (approved) _origOpen(url, target, features);
    });
    return null;
  };

  // ── HTMLFormElement.prototype.submit / requestSubmit ──────────────────────

  HTMLFormElement.prototype.submit = function () {
    const form = this;
    askShani({ action: "fill_form", target: form.action || location.href }, (approved) => {
      if (approved) _origSubmit.call(form);
    });
  };

  if (_origReqSubmit) {
    HTMLFormElement.prototype.requestSubmit = function (submitter) {
      const form = this;
      askShani({ action: "fill_form", target: form.action || location.href }, (approved) => {
        if (approved) _origReqSubmit.call(form, submitter);
      });
    };
  }

  // ── Script-driven click on <a> (isTrusted === false) ─────────────────────

  document.addEventListener(
    "click",
    (event) => {
      if (event.isTrusted) return; // Pass through user interactions as-is
      const anchor = event.target && event.target.closest("a[href]");
      if (!anchor) return;
      const href = anchor.getAttribute("href");
      if (!href || href.startsWith("#")) return;

      event.preventDefault();
      event.stopImmediatePropagation();

      const url = new URL(href, location.href).href;
      askShani({ action: "navigate", target: url }, (approved) => {
        // After approval, call the original assign directly (calling the patched
        // Location.prototype.assign would trigger a double query to Shani)
        if (approved) _origAssign.call(location, url);
      });
    },
    true // capture phase
  );

  // ── history.pushState / replaceState ─────────────────────────────────────

  history.pushState = function (state, title, url) {
    if (!url) { _origPushState(state, title, url); return; }
    const resolved = new URL(String(url), location.href).href;
    askShani({ action: "navigate", target: resolved }, (approved) => {
      if (approved) _origPushState(state, title, url);
    });
  };

  history.replaceState = function (state, title, url) {
    if (!url) { _origReplaceState(state, title, url); return; }
    const resolved = new URL(String(url), location.href).href;
    askShani({ action: "navigate", target: resolved }, (approved) => {
      if (approved) _origReplaceState(state, title, url);
    });
  };

  // ── Location.prototype.assign / replace ──────────────────────────────────
  // Patching at the prototype level captures all calls made via instances
  // (as opposed to patching as an instance property).

  Location.prototype.assign = function (url) {
    if (!url) { _origAssign.call(this, url); return; }
    const resolved = new URL(String(url), location.href).href;
    askShani({ action: "navigate", target: resolved }, (approved) => {
      if (approved) _origAssign.call(this, url);
    });
  };

  Location.prototype.replace = function (url) {
    if (!url) { _origReplace.call(this, url); return; }
    const resolved = new URL(String(url), location.href).href;
    askShani({ action: "navigate", target: resolved }, (approved) => {
      if (approved) _origReplace.call(this, url);
    });
  };

  // ── location.href setter ──────────────────────────────────────────────────
  // Bug 2 fix: patch Location.prototype rather than the location instance.
  // Object.defineProperty on an instance can silently fail under Chrome's
  // security model, so the prototype is patched directly.

  if (_hrefDesc && _hrefDesc.set) {
    const _origHrefSet = _hrefDesc.set;
    try {
      Object.defineProperty(Location.prototype, "href", {
        configurable: true,
        enumerable: true,
        get: _hrefDesc.get,
        set(url) {
          if (!url) { _origHrefSet.call(this, url); return; }
          const resolved = new URL(String(url), location.href).href;
          askShani({ action: "navigate", target: resolved }, (approved) => {
            if (approved) _origHrefSet.call(this, url);
          });
        },
      });
    } catch (_e) {
      // Some browsers may restrict rewriting Location.prototype
    }
  }

  // ── fetch Proxy (Approach A) ──────────────────────────────────────────────
  // Intercept Shani approval when Claude in Chrome fetches an external site.
  // Requests to claude.ai itself and same-origin requests pass through to protect UX.

  function _fetchShouldIntercept(url) {
    try {
      const parsed = new URL(url, location.href);
      if (parsed.origin === "https://claude.ai") return false;
      if (parsed.origin === location.origin)     return false;
      const h = parsed.hostname;
      for (const suffix of _PASSTHROUGH_HOST_SUFFIXES) {
        if (h === suffix.slice(1) || h.endsWith(suffix)) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  window.fetch = new Proxy(_origFetch, {
    apply(target, thisArg, args) {
      const [resource, init] = args;
      const url =
        typeof resource === "string" ? resource
        : resource instanceof URL    ? resource.href
        :                              resource?.url || "";

      if (!_fetchShouldIntercept(url)) {
        return Reflect.apply(target, thisArg, args);
      }

      const method = ((init && init.method) || "GET").toUpperCase();
      const action = method === "GET" ? "scrape" : "browser_fetch";

      return new Promise((resolve, reject) => {
        askShani({ action, target: url }, (approved) => {
          if (approved) resolve(Reflect.apply(target, thisArg, args));
          else reject(new Error("Shani: fetch denied — " + url));
        });
      });
    },
  });

  // ── XMLHttpRequest Proxy (Approach A supplement) ──────────────────────────
  // Intercept XHR in the same way as fetch. Record the URL in open() and
  // evaluate it in send().

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._shaniMethod = method;
    this._shaniUrl    = url;
    return _origXHROpen.apply(this, [method, url, ...rest]);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const url = this._shaniUrl || "";
    if (!_fetchShouldIntercept(url)) {
      return _origXHRSend.apply(this, [body]);
    }

    const method = ((this._shaniMethod) || "GET").toUpperCase();
    const action = method === "GET" ? "scrape" : "browser_fetch";
    const xhr    = this;

    askShani({ action, target: url }, (approved) => {
      if (approved) {
        _origXHRSend.apply(xhr, [body]);
      } else {
        xhr.dispatchEvent(new ProgressEvent("error"));
      }
    });
  };
})();
