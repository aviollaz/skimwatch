// Injected into every page before any of its own scripts run. It only observes:
// it records eval'd code, who listens to form inputs and what goes over WebRTC, and it stops form submissions
// so filling canary values can never place an order or send a real request on its own.
(() => {
  const log = [];
  Object.defineProperty(window, "__skimwatch", { value: log, enumerable: false });

  const caller = () => {
    const stack = (new Error().stack || "").split("\n");
    for (const line of stack) {
      const m = line.match(/(https?:\/\/[^\s)]+?)(?::\d+:\d+)?\)?$/);
      if (m) return m[1];
    }
    return "inline";
  };
  const record = (kind, detail) => {
    if (log.length < 500) log.push({ kind, detail: String(detail).slice(0, 4000), source: caller() });
  };

  const realEval = window.eval;
  window.eval = function (code) {
    record("eval", code);
    return realEval.call(this, code);
  };
  const RealFunction = window.Function;
  const WrappedFunction = function (...args) {
    record("function", args.length ? args[args.length - 1] : "");
    return RealFunction.apply(this, args);
  };
  WrappedFunction.prototype = RealFunction.prototype;
  window.Function = WrappedFunction;

  const realAdd = EventTarget.prototype.addEventListener;
  const watched = new Set(["keydown", "keyup", "keypress", "input", "change", "blur", "paste", "submit"]);
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    if (watched.has(type)) {
      const el = this;
      const desc = el && el.tagName
        ? `${el.tagName.toLowerCase()}[name=${el.getAttribute("name") || ""}][autocomplete=${el.getAttribute("autocomplete") || ""}]`
        : (el === document ? "document" : el === window ? "window" : "other");
      record("listener", `${type} on ${desc}`);
    }
    return realAdd.call(this, type, fn, opts);
  };

  // WebRTC. A data channel moves data as UDP to a peer: no HTTP request, nothing for CSP
  // connect-src or the network log to see. PaperCut (2026) used one both to receive its
  // skimmer and to send the stolen cards. Wrappers are Proxies so they still look native
  // to code that checks Function.prototype.toString.
  const describeData = (d) => {
    if (typeof d === "string") return d;
    try {
      if (d instanceof ArrayBuffer) return new TextDecoder().decode(d);
      if (ArrayBuffer.isView(d)) return new TextDecoder().decode(d);
    } catch (e) {}
    return "[" + Object.prototype.toString.call(d) + "]";
  };
  const wrapMethod = (proto, name, kind, describe) => {
    if (!proto || typeof proto[name] !== "function") return;
    proto[name] = new Proxy(proto[name], {
      apply(target, self, args) {
        try { record(kind, describe(args)); } catch (e) {}
        return Reflect.apply(target, self, args);
      },
    });
  };
  const RealPC = window.RTCPeerConnection;
  if (typeof RealPC === "function") {
    const proto = RealPC.prototype;
    const PC = new Proxy(RealPC, {
      construct(target, args, newTarget) {
        let servers = "[]";
        try { servers = JSON.stringify((args[0] && args[0].iceServers) || []); } catch (e) {}
        record("webrtc-peer", servers);
        return Reflect.construct(target, args, newTarget);
      },
    });
    window.RTCPeerConnection = PC;
    if (window.webkitRTCPeerConnection === RealPC) window.webkitRTCPeerConnection = PC;
    wrapMethod(proto, "createDataChannel", "webrtc-channel", (a) => String(a[0]));
    wrapMethod(proto, "setRemoteDescription", "webrtc-remote", (a) => (a[0] && a[0].sdp) || "");
    wrapMethod(proto, "addIceCandidate", "webrtc-remote", (a) => (a[0] && (a[0].candidate || "")) || "");
  }
  if (window.RTCDataChannel) {
    wrapMethod(RTCDataChannel.prototype, "send", "webrtc-send", (a) => describeData(a[0]));
  }

  // Never let a form leave the page during a scan.
  realAdd.call(document, "submit", (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);
  HTMLFormElement.prototype.submit = function () { record("blocked-submit", this.action); };
})();
