/**
 * Shani Chrome Extension — Page Bridge (MAIN world)
 *
 * document_start + world:"MAIN" で注入され、Claude in Chrome が使う
 * ブラウザ API を monkey-patch して Shani ガバナンスを通す。
 *
 * MAIN world では chrome.runtime が使えないため、
 * window.postMessage で ISOLATED world の content.js と通信する。
 */

(function () {
  "use strict";

  // ── ユーティリティ ────────────────────────────────────────────────────────

  let _reqCounter = 0;
  function nextId() {
    return "pb-" + Date.now() + "-" + ++_reqCounter;
  }

  // 同一 action:target への重複リクエストを排除する。
  // key: "action:target" → { requestId, callbacks[] }
  const _inflightRequests = new Map();

  /**
   * content.js に承認を問い合わせ、コールバックで結果を受け取る。
   * 同一 action+target が既に HITL 待機中の場合はコールバックをキューに積み、
   * 新たなリクエストを送らない（重複排除）。
   * @param {object} payload  - action / target などのリクエスト情報
   * @param {function} cb     - cb(approved: boolean) を呼ぶ
   */
  function askShani(payload, cb) {
    // scrape / browser_fetch はホスト名単位で重複排除する。
    // 広告スクリプトが同一ドメインへ大量のリクエストを送っても
    // 最初の1件のみ Shani に問い合わせ、残りは同じ判断に従う。
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

  // ── 既知の広告・アナリティクス・トラッキングドメイン ────────────────────
  // これらは広告スクリプトが大量に呼ぶ外部リクエストであり、
  // Claude の意図的なアクションではないのでガバナンスをスキップする。
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

  // ── 元の関数・ディスクリプタを先にすべて保存 ──────────────────────────────
  // 後続のパッチ処理が互いに干渉しないよう、パッチ前にキャプチャする。

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

  // ── <a> への script-driven click (isTrusted === false) ───────────────────

  document.addEventListener(
    "click",
    (event) => {
      if (event.isTrusted) return; // ユーザー操作はそのまま通す
      const anchor = event.target && event.target.closest("a[href]");
      if (!anchor) return;
      const href = anchor.getAttribute("href");
      if (!href || href.startsWith("#")) return;

      event.preventDefault();
      event.stopImmediatePropagation();

      const url = new URL(href, location.href).href;
      askShani({ action: "navigate", target: url }, (approved) => {
        // 承認後は元の assign を直接呼ぶ（パッチ済み Location.prototype.assign を
        // 経由すると二重に Shani へ問い合わせが起きるため）
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
  // prototype レベルでパッチすることで、インスタンス経由のすべての呼び出しを
  // 捕捉できる（インスタンスプロパティとしてパッチした場合との違い）。

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

  // ── location.href setter ───────────────────────────────────────────────────
  // Bug 2 修正: location インスタンスではなく Location.prototype にパッチする。
  // インスタンスへの Object.defineProperty は Chrome のセキュリティモデルで
  // サイレントに失敗する場合があるため、prototype を直接書き換える。

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
      // ブラウザによって Location.prototype の書き換えが制限される場合がある
    }
  }

  // ── fetch Proxy (アプローチ A) ────────────────────────────────────────────
  // Claude in Chrome が外部サイトへ fetch する際に Shani の承認を挟む。
  // claude.ai 自身と同一オリジンのリクエストはそのまま通過させ UX を守る。

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

  // ── XMLHttpRequest Proxy (アプローチ A 補完) ──────────────────────────────
  // fetch と同様に XHR も傍受する。open() で URL を記録し send() で判定する。

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
