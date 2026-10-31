package static

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

// Context says where a piece of code was found and which hosts the store trusts.
type Context struct {
	Target   string
	PageURL  string
	Location string
	Scope    *domains.Scope
	depth    int // how many layers of encoding were peeled to reach this code
}

// A signal is one suspicious behavior. Most are harmless on their own (analytics libraries
// listen to inputs, monitoring tools wrap fetch); findings come from combining them.
type signal struct {
	name     string
	re       *regexp.Regexp
	evidence string
}

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

var (
	reEvalDecoded = re(`(?i)\b(eval|Function|setTimeout|setInterval)\s*\(\s*(window\.)?(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(`)
	reEval        = re(`\beval\s*\(`)
	reNewFunction = re(`\bnew\s+Function\s*\(`)
	reTimerString = re(`\bset(Timeout|Interval)\s*\(\s*["'\x60]`)
	rePacker      = re(`eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)`)
	reObfVars     = re(`\b_0x[0-9a-f]{4,6}\b`)

	reCardAccess = re(`(?i)(cc-number|cc-csc|cc-exp|card[_-]?number|cardnum|\bcvv\b|\bcvc\b|security[_-]?code|numero[_-]?tarjeta|nro[_-]?tarjeta|card[_-]?holder|\bcc_?num)`)
	reCheckout   = re(`(?i)(vtexjs\.checkout|orderForm|checkout\.(payment|billing)|payment[_-]?form|/checkout)`)
	reListener   = re(`addEventListener\s*\(\s*["'](keydown|keyup|keypress|input|change|blur|submit|paste)["']|\.on(keydown|keyup|keypress|input|change|submit)\s*=`)
	reHarvest    = re(`new\s+FormData\s*\(|querySelectorAll\s*\(\s*["'](input|select|form)|\.elements\b|document\.forms`)
	reNetHook    = re(`(window\.fetch|\bfetch)\s*=\s*(function|async|\(|[a-zA-Z_$])|XMLHttpRequest\.prototype\.(open|send|setRequestHeader)\s*=|navigator\.sendBeacon\s*=|defineProperty\s*\(\s*(window|XMLHttpRequest\.prototype|HTMLFormElement\.prototype)`)

	reBeacon    = re(`navigator\.sendBeacon\s*\(`)
	reWebSocket = re(`new\s+WebSocket\s*\(`)
	reFetchOut  = re(`fetch\s*\(\s*["'\x60]https?://|\.open\s*\(\s*["']POST["']\s*,\s*["'\x60]https?://`)
	reImagePing = re(`new\s+Image\s*\(\s*\d*\s*,?\s*\d*\s*\)[\s\S]{0,200}?\.src\s*=|\.src\s*=\s*["'\x60]https?://[^"'\x60]+["'\x60]\s*\+`)
	reAbsURL    = re(`(?i)(?:https?:|wss?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/[^\s"'\x60)]*)?`)

	reAntiDebug = re(`\bdebugger\b|outerWidth\s*-\s*(window\.)?innerWidth|outerHeight\s*-\s*(window\.)?innerHeight|devtools`)
	reMiner     = re(`(?i)(coinhive|coin-hive|cryptoloot|crypto-loot|cryptonight|webminepool|deepminer|jsecoin|stratum\+tcp|minero\.cc|monerominer|\.startMining\s*\()`)
	reRedirect  = re(`(window\.|document\.|top\.)?location(\.href)?\s*=[^=]|location\.(replace|assign)\s*\(`)
	reCloak     = re(`(?i)document\.referrer|navigator\.userAgent[\s\S]{0,80}(bot|crawl|spider|google)|navigator\.webdriver`)
	reDocWrite  = re(`document\.write(ln)?\s*\([^)]*<\s*(script|iframe)`)
	reInject    = re(`createElement\s*\(\s*["'](script|iframe)["']\s*\)`)
	reCodeish   = re(`function\s*\(|=>|\bdocument\.|\bwindow\.|\bvar\s|\blet\s|\bconst\s|https?://|<script`)
)

// AnalyzeJS inspects one piece of code. It never executes anything.
func AnalyzeJS(code string, ctx Context) []model.Finding {
	if strings.TrimSpace(code) == "" {
		return nil
	}
	var out []model.Finding
	add := func(rule string, sev model.Severity, title, detail, evidence string) {
		loc := ctx.Location
		if ctx.depth > 0 {
			loc = fmt.Sprintf("%s (decoded, layer %d)", ctx.Location, ctx.depth)
		}
		out = append(out, model.Finding{
			Layer: model.LayerStatic, Rule: rule, Severity: sev, Target: ctx.Target, PageURL: ctx.PageURL,
			Location: loc, Title: title, Detail: detail, Evidence: model.Truncate(evidence, 240),
		})
	}
	inHandler := strings.Contains(ctx.Location, "handler") || strings.Contains(ctx.Location, "javascript:")

	// 1. Code that decodes itself and runs the result: the signature of an injected payload.
	if m := find(reEvalDecoded, code); m != "" {
		sev := model.High
		title := "Runs code it decodes at runtime"
		if inHandler {
			sev = model.Critical
			title = "Encoded code executed from an HTML event handler"
		}
		add("eval-decoded", sev, title,
			"Decoding a string and passing it to eval/Function hides the real behavior from anyone reading the page. "+
				"Legitimate libraries almost never do this; injected skimmers almost always do. "+
				"In an event handler like onerror it is the classic way to smuggle a script through a content field.",
			m)
	}
	if m := find(rePacker, code); m != "" {
		add("packed-code", model.High, "Packed with an eval-based packer",
			"Dean Edwards-style packing unpacks itself with eval. Common in old themes, but also a favorite way to hide injected code.", m)
	}
	if n := len(reObfVars.FindAllStringIndex(code, -1)); n >= 20 {
		add("obfuscator", model.Medium, "Obfuscated with an automated obfuscator",
			fmt.Sprintf("%d identifiers like _0x1a2b are the fingerprint of obfuscator.io-style tools. Review who owns this script.", n),
			find(reObfVars, code))
	}

	// 2. Hidden payloads: decode them and analyze the result as code.
	revealed := false
	if ctx.depth < 3 {
		for _, h := range RevealHidden(code) {
			if !reCodeish.MatchString(h.Text) {
				continue
			}
			add("hidden-payload", model.Medium, "Code hidden inside an encoded string",
				fmt.Sprintf("A %s-encoded string decodes to code. Its decoded content is analyzed below as its own layer.", h.Encoding),
				h.Text)
			revealed = true
			inner := ctx
			inner.depth++
			out = append(out, AnalyzeJS(h.Text, inner)...)
		}
	}
	if blobs := HighEntropyStrings(code); len(blobs) > 0 && ctx.depth == 0 && !revealed {
		add("high-entropy", model.Low, "Long random-looking string",
			"Encrypted or packed data embedded in code. Often harmless (licenses, compressed data), but worth knowing about.", blobs[0])
	}

	// 3. The skimmer pattern: something that reads payment data or hooks the checkout,
	// and something that sends data to a host the store does not control.
	external := externalHosts(code, ctx.Scope)
	collects := find(reCardAccess, code)
	checkout := find(reCheckout, code)
	listens := find(reListener, code)
	harvests := find(reHarvest, code)
	hooks := find(reNetHook, code)
	sends := firstNonEmpty(find(reBeacon, code), find(reWebSocket, code), find(reImagePing, code), find(reFetchOut, code))

	exfilTarget := ""
	if len(external) > 0 {
		exfilTarget = external[0]
	}
	switch {
	case (collects != "" || hooks != "") && sends != "" && exfilTarget != "":
		add("skimmer-pattern", model.Critical, "Probable payment skimmer",
			fmt.Sprintf("This code %s and sends data to %s, a host outside the store. "+
				"That combination is how Magecart-style skimmers work.",
				map[bool]string{true: "reads payment card fields", false: "hooks the browser's network or checkout APIs"}[collects != ""], exfilTarget),
			firstNonEmpty(collects, hooks)+" … "+sends)
	case checkout != "" && sends != "" && exfilTarget != "":
		add("checkout-exfil", model.High, "Checkout-related code sends data to an outside host",
			"This code references the checkout ("+checkout+") and sends data to "+exfilTarget+". Confirm that host belongs to the payment provider.",
			checkout+" … "+sends)
	case hooks != "" && exfilTarget != "":
		add("network-hook-external", model.High, "Wraps network APIs and references an outside host",
			"Overriding fetch/XHR lets code read every request the page makes, including checkout calls. "+
				"Monitoring tools do this too, so confirm the host "+exfilTarget+" belongs to one.", hooks)
	case hooks != "":
		add("network-hook", model.Low, "Wraps the browser's network APIs",
			"Overriding fetch or XMLHttpRequest is common in analytics and error monitoring, and also the first step of a skimmer.", hooks)
	case collects != "" && (listens != "" || harvests != ""):
		add("card-field-access", model.Medium, "Reads payment card fields",
			"Code listens to or collects card inputs. Expected in the payment provider's own script; suspicious anywhere else.",
			collects)
	}
	if sends != "" && exfilTarget != "" && collects == "" && checkout == "" && hooks == "" {
		add("beacon-external", model.Info, "Sends data to an outside host",
			"Beacons, WebSockets or image pings to "+exfilTarget+". Usually analytics; listed so new destinations stand out.", sends)
	}

	// 4. Other client-side attacks.
	if m := find(reMiner, code); m != "" {
		add("cryptominer", model.Critical, "Cryptocurrency miner",
			"In-browser mining uses visitors' CPUs without consent. It is never legitimate on a store.", m)
	}
	if r := find(reRedirect, code); r != "" {
		if c := find(reCloak, code); c != "" {
			add("cloaked-redirect", model.High, "Redirect that depends on who is visiting",
				"Redirecting only some visitors, based on the referrer, the user agent or automation detection, is how "+
					"malicious redirects hide from site owners and crawlers.", c+" … "+r)
		}
	}
	if m := find(reAntiDebug, code); m != "" && ctx.depth == 0 {
		add("anti-debugging", model.Medium, "Tries to detect developer tools",
			"Skimmers stop running when someone opens DevTools to inspect them. Legitimate store code has no reason to care.", m)
	}
	if m := find(reDocWrite, code); m != "" {
		add("document-write-script", model.Low, "Writes a script or iframe with document.write",
			"An old loading technique that is also used to inject code without it appearing in the page source.", m)
	}
	if find(reInject, code) != "" && exfilTarget != "" {
		add("dynamic-loader", model.Medium, "Loads a script or iframe from an outside host at runtime",
			"Code that creates script tags pointing to "+exfilTarget+" adds code that is not in the page source. "+
				"The runtime layer records what actually gets loaded.", find(reInject, code))
	}
	if ctx.depth == 0 {
		if m := find(reEval, code); m != "" && find(reEvalDecoded, code) == "" && find(rePacker, code) == "" {
			add("eval", model.Info, "Uses eval", "Dynamic code execution. Common in older libraries; noted for context.", m)
		}
		if m := firstNonEmpty(find(reNewFunction, code), find(reTimerString, code)); m != "" && find(reEvalDecoded, code) == "" {
			add("dynamic-code", model.Info, "Builds code from strings", "new Function or setTimeout with a string. Noted for context.", m)
		}
	}
	return out
}

// externalHosts lists hosts referenced in code that the store does not control.
func externalHosts(code string, scope *domains.Scope) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reAbsURL.FindAllStringSubmatch(code, 200) {
		host := strings.ToLower(m[1])
		if seen[host] || isNoise(host) {
			continue
		}
		seen[host] = true
		if scope == nil || !scope.Trusted(host) {
			out = append(out, host)
		}
	}
	return out
}

// Hosts that appear in code as namespaces or documentation, never as destinations.
func isNoise(host string) bool {
	switch host {
	case "www.w3.org", "w3.org", "schema.org", "www.ecma-international.org", "github.com", "developer.mozilla.org":
		return true
	}
	return strings.HasSuffix(host, ".js") || strings.HasSuffix(host, ".min") || strings.HasSuffix(host, ".prototype")
}

// find returns the match with a little surrounding context, or "" when there is none.
func find(r *regexp.Regexp, s string) string {
	loc := r.FindStringIndex(s)
	if loc == nil {
		return ""
	}
	start, end := loc[0]-40, loc[1]+60
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
