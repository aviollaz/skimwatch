// Package static analyzes HTML and JavaScript without executing anything.
package static

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Document is everything on a page that can carry or load code.
type Document struct {
	BaseURL     *url.URL
	InlineJS    []Snippet // <script> bodies without src
	ExternalJS  []ExternalScript
	Handlers    []Snippet // inline event handlers: onerror, onload, onclick...
	JSURLs      []Snippet // href="javascript:..." and similar
	Iframes     []Iframe
	Forms       []Form
	MetaRefresh []string // target URLs of <meta http-equiv="refresh">
}

// Snippet is code plus a human-readable description of where it sits.
type Snippet struct {
	Location string
	Code     string
}

// ExternalScript is a <script src>. Integrity is the SRI hash, if any.
type ExternalScript struct {
	URL       string
	Integrity string
	Async     bool
}

// Iframe records what is needed to spot invisible frames to unknown hosts.
type Iframe struct {
	URL    string
	Hidden bool
}

// Form records where a form posts and whether it asks for payment data.
type Form struct {
	Action        string
	Method        string
	HasCardFields bool
}

// ParseHTML walks the page once and collects every place code can live.
func ParseHTML(body []byte, pageURL string) (*Document, error) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("parsing page URL: %w", err)
	}
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parsing HTML: %w", err)
	}
	d := &Document{BaseURL: base}
	inline := 0
	var formStack []*Form

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := n.Data
			attrs := attrMap(n)

			// <base href> changes how every relative URL resolves.
			if tag == "base" {
				if h, ok := attrs["href"]; ok {
					if b, err := base.Parse(h); err == nil {
						d.BaseURL = b
					}
				}
			}

			for _, a := range n.Attr {
				name := strings.ToLower(a.Key)
				switch {
				case strings.HasPrefix(name, "on") && len(name) > 2 && strings.TrimSpace(a.Val) != "":
					d.Handlers = append(d.Handlers, Snippet{
						Location: fmt.Sprintf("%s handler on <%s>", name, tag),
						Code:     a.Val,
					})
				case isURLAttr(name) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.Val)), "javascript:"):
					d.JSURLs = append(d.JSURLs, Snippet{
						Location: fmt.Sprintf("%s=javascript: on <%s>", name, tag),
						Code:     strings.TrimSpace(a.Val)[len("javascript:"):],
					})
				}
			}

			switch tag {
			case "script":
				if !isJavaScriptType(attrs["type"]) {
					break
				}
				if src, ok := attrs["src"]; ok && strings.TrimSpace(src) != "" {
					d.ExternalJS = append(d.ExternalJS, ExternalScript{
						URL:       d.resolve(src),
						Integrity: attrs["integrity"],
						Async:     hasAttr(n, "async") || hasAttr(n, "defer"),
					})
				} else {
					inline++
					d.InlineJS = append(d.InlineJS, Snippet{
						Location: fmt.Sprintf("inline script #%d", inline),
						Code:     textContent(n),
					})
				}
			case "iframe", "frame":
				if src := attrs["src"]; src != "" {
					d.Iframes = append(d.Iframes, Iframe{URL: d.resolve(src), Hidden: isHidden(attrs)})
				}
			case "meta":
				if strings.EqualFold(attrs["http-equiv"], "refresh") {
					if target := refreshTarget(attrs["content"]); target != "" {
						d.MetaRefresh = append(d.MetaRefresh, d.resolve(target))
					}
				}
			case "form":
				f := &Form{Action: d.resolve(attrs["action"]), Method: strings.ToUpper(attrs["method"])}
				if attrs["action"] == "" {
					f.Action = d.BaseURL.String()
				}
				d.Forms = append(d.Forms, *f)
				formStack = append(formStack, &d.Forms[len(d.Forms)-1])
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c)
				}
				formStack = formStack[:len(formStack)-1]
				return
			case "input", "select":
				if len(formStack) > 0 && isCardField(attrs) {
					formStack[len(formStack)-1].HasCardFields = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return d, nil
}

func (d *Document) resolve(ref string) string {
	u, err := d.BaseURL.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ref
	}
	return u.String()
}

func attrMap(n *html.Node) map[string]string {
	m := make(map[string]string, len(n.Attr))
	for _, a := range n.Attr {
		m[strings.ToLower(a.Key)] = a.Val
	}
	return m
}

func hasAttr(n *html.Node, name string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return true
		}
	}
	return false
}

func textContent(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

func isURLAttr(name string) bool {
	switch name {
	case "href", "src", "action", "formaction", "data", "xlink:href":
		return true
	}
	return false
}

// Only these types are executed by browsers; JSON-LD, templates and the like are data.
func isJavaScriptType(t string) bool {
	t = strings.ToLower(strings.TrimSpace(strings.SplitN(t, ";", 2)[0]))
	switch t {
	case "", "text/javascript", "application/javascript", "module", "text/ecmascript",
		"application/ecmascript", "application/x-javascript", "text/jscript":
		return true
	}
	return false
}

func isHidden(attrs map[string]string) bool {
	if _, ok := attrs["hidden"]; ok {
		return true
	}
	style := strings.ReplaceAll(strings.ToLower(attrs["style"]), " ", "")
	if strings.Contains(style, "display:none") || strings.Contains(style, "visibility:hidden") ||
		strings.Contains(style, "opacity:0") {
		return true
	}
	for _, dim := range []string{"width", "height"} {
		v := strings.TrimSpace(strings.TrimSuffix(attrs[dim], "px"))
		if v == "0" || v == "1" {
			return true
		}
		if strings.Contains(style, dim+":0") || strings.Contains(style, dim+":1px") {
			return true
		}
	}
	return false
}

func refreshTarget(content string) string {
	_, rest, ok := strings.Cut(content, ";")
	if !ok {
		return ""
	}
	rest = strings.TrimSpace(rest)
	if len(rest) >= 4 && strings.EqualFold(rest[:4], "url=") {
		rest = rest[4:]
	}
	return strings.Trim(rest, `'" `)
}

// isCardField recognizes payment inputs by the hints browsers and payment forms use.
func isCardField(attrs map[string]string) bool {
	hay := strings.ToLower(attrs["name"] + " " + attrs["id"] + " " + attrs["autocomplete"] + " " + attrs["placeholder"])
	return ContainsCardHint(hay)
}

var cardHints = []string{
	"cc-number", "cc-csc", "cc-exp", "cardnumber", "card-number", "card_number", "cardnum",
	"cvv", "cvc", "csc", "securitycode", "security-code", "numero-tarjeta", "numerotarjeta",
	"nro_tarjeta", "tarjeta", "expiry", "expiration", "vencimiento",
}

// ContainsCardHint reports whether text mentions a payment-card field.
func ContainsCardHint(s string) bool {
	s = strings.ToLower(s)
	for _, h := range cardHints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}
