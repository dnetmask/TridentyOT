// Minimal window._.memoize/throttle shim -- cytoscape-edgehandles.js's UMD
// build falls back to a global `_` (lodash) when no CommonJS/AMD loader is
// present (see its own header: `root["_"]["memoize"]`/`root["_"]["throttle"]`).
// Vendoring the whole of lodash for two small, well-known utilities would be
// wasteful; these two implementations cover exactly how edgehandles calls
// them (memoize keyed by the single node argument, throttle with a fixed
// wait) without pulling in a dependency.
(function () {
  window._ = window._ || {};

  window._.memoize = function memoize(fn) {
    var cache = new Map();
    var memoized = function (arg) {
      if (cache.has(arg)) return cache.get(arg);
      var result = fn.apply(this, arguments);
      cache.set(arg, result);
      return result;
    };
    memoized.cache = cache;
    return memoized;
  };

  window._.throttle = function throttle(fn, wait) {
    var timeout = null;
    var lastArgs = null;
    var lastThis = null;
    var lastCallTime = 0;

    function invoke() {
      lastCallTime = Date.now();
      timeout = null;
      fn.apply(lastThis, lastArgs);
    }

    return function throttled() {
      var now = Date.now();
      var remaining = wait - (now - lastCallTime);
      lastArgs = arguments;
      lastThis = this;
      if (remaining <= 0) {
        if (timeout) { clearTimeout(timeout); timeout = null; }
        invoke();
      } else if (!timeout) {
        timeout = setTimeout(invoke, remaining);
      }
    };
  };
})();
