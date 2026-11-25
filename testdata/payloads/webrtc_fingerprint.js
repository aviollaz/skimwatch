// DEFANGED TEST FIXTURE: the common, legitimate use of WebRTC on stores. Fraud-detection
// libraries open a peer connection to a public STUN server to learn the visitor's IP.
(function () {
  var pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
  pc.onicecandidate = function (e) { if (e.candidate) window.__ip = e.candidate.candidate; };
  pc.createOffer().then(function (o) { pc.setLocalDescription(o); });
})();
