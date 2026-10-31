// Injected into every page before any of its own scripts run. It only observes:
// it records eval'd code and who listens to form inputs, and it stops form submissions
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

  // Never let a form leave the page during a scan.
  realAdd.call(document, "submit", (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);
  HTMLFormElement.prototype.submit = function () { record("blocked-submit", this.action); };
})();
