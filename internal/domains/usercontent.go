package domains

import (
	"net/url"
	"path"
	"strings"
)

// UserCode describes a script served by a public CDN straight out of someone's repository
// or package. The CDN itself is trustworthy, which is the problem: anyone can open a GitHub
// account, push a file and have jsDelivr serve it from a domain every store already loads.
// The 2026 "PaperCut" attack on 80 US newspapers loaded its skimmer this way, from
// cdn.jsdelivr.net/gh/<throwaway account>/<repo>@main/jQuery.1.3.1.js.
type UserCode struct {
	Service string // "github", "npm"
	Owner   string // GitHub account or npm scope/package
	Repo    string // GitHub repository or npm package
	Ref     string // branch, tag or version after "@", if any
	File    string // file name, without directories
	Mutable bool   // the ref can change under the same URL: a branch, "latest" or no ref at all
}

// Account is "owner/repo" for GitHub and the package name for npm.
func (u UserCode) Account() string {
	if u.Service == "github" {
		return u.Owner + "/" + u.Repo
	}
	return u.Repo
}

// ParseUserCode recognizes scripts served from code-hosting CDNs. ok is false for every
// other URL, including the same CDNs' curated libraries (cdnjs) and Google's hosted libraries.
func ParseUserCode(rawURL string) (UserCode, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return UserCode{}, false
	}
	host := strings.ToLower(u.Hostname())
	parts := splitPath(u.Path)
	file := ""
	if len(parts) > 0 {
		file = path.Base(u.Path)
	}

	switch {
	// cdn.jsdelivr.net/gh/user/repo@ref/file, fastly.jsdelivr.net, gcore.jsdelivr.net...
	case strings.HasSuffix(host, "jsdelivr.net") && len(parts) >= 3 && parts[0] == "gh":
		repo, ref := splitRef(parts[2])
		return UserCode{Service: "github", Owner: parts[1], Repo: repo, Ref: ref, File: file, Mutable: mutableRef(ref)}, true
	case strings.HasSuffix(host, "jsdelivr.net") && len(parts) >= 2 && parts[0] == "npm":
		pkg, ref := npmPackage(parts[1:])
		return UserCode{Service: "npm", Repo: pkg, Ref: ref, File: file, Mutable: mutableRef(ref)}, true
	// unpkg.com/package@version/file
	case host == "unpkg.com" && len(parts) >= 1:
		pkg, ref := npmPackage(parts)
		return UserCode{Service: "npm", Repo: pkg, Ref: ref, File: file, Mutable: mutableRef(ref)}, true
	// raw.githubusercontent.com/user/repo/ref/file
	case host == "raw.githubusercontent.com" && len(parts) >= 3:
		return UserCode{Service: "github", Owner: parts[0], Repo: parts[1], Ref: parts[2], File: file, Mutable: mutableRef(parts[2])}, true
	// raw.githack.com, rawcdn.githack.com, cdn.statically.io/gh/: unofficial GitHub mirrors
	case (host == "raw.githack.com" || host == "rawcdn.githack.com") && len(parts) >= 3:
		return UserCode{Service: "github", Owner: parts[0], Repo: parts[1], Ref: parts[2], File: file, Mutable: mutableRef(parts[2])}, true
	case host == "cdn.statically.io" && len(parts) >= 4 && parts[0] == "gh":
		return UserCode{Service: "github", Owner: parts[1], Repo: parts[2], Ref: parts[3], File: file, Mutable: mutableRef(parts[3])}, true
	// user.github.io/repo/file: GitHub Pages
	case strings.HasSuffix(host, ".github.io"):
		owner := strings.TrimSuffix(host, ".github.io")
		repo := ""
		if len(parts) > 1 {
			repo = parts[0]
		}
		return UserCode{Service: "github", Owner: owner, Repo: repo, File: file, Mutable: true}, true
	}
	return UserCode{}, false
}

// Official homes of libraries that attackers name their files after. A file called
// "jquery.min.js" served from any other account is pretending to be something it is not.
var officialLibraries = map[string][]string{
	"jquery":      {"jquery/jquery", "jquery", "jquery-ui", "jquery-migrate"},
	"bootstrap":   {"twbs/bootstrap", "bootstrap"},
	"lodash":      {"lodash/lodash", "lodash"},
	"react":       {"facebook/react", "react", "react-dom"},
	"vue":         {"vuejs/vue", "vuejs/core", "vue"},
	"angular":     {"angular/angular", "angular/angular.js", "angular"},
	"polyfill":    {"polyfill"},
	"analytics":   {},
	"gtag":        {},
	"gtm":         {},
	"mercadopago": {"mercadopago/sdk-js", "@mercadopago/sdk-js"},
	"stripe":      {"@stripe/stripe-js"},
}

// ImpersonatedLibrary returns the well-known library whose name the file borrows while being
// served from someone else's account, or "".
func (u UserCode) ImpersonatedLibrary() string {
	name := strings.ToLower(u.File)
	for lib, homes := range officialLibraries {
		if !strings.Contains(name, lib) {
			continue
		}
		acct := strings.ToLower(u.Account())
		official := false
		for _, h := range homes {
			if acct == h {
				official = true
			}
		}
		if !official {
			return lib
		}
	}
	return ""
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func splitRef(s string) (name, ref string) {
	if i := strings.LastIndexByte(s, '@'); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// npmPackage reads "pkg@1.2.3" or "@scope/pkg@1.2.3" from the start of a path.
func npmPackage(parts []string) (pkg, ref string) {
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		name, ref := splitRef(parts[1])
		return parts[0] + "/" + name, ref
	}
	return splitRef(parts[0])
}

// mutableRef reports whether a ref can point at different code tomorrow. Exact versions,
// tags that look like versions and commit hashes are pinned; branches and "latest" are not.
func mutableRef(ref string) bool {
	r := strings.ToLower(ref)
	switch {
	case r == "", r == "latest", r == "main", r == "master", r == "dev", r == "develop", r == "gh-pages":
		return true
	case isHex(r) && len(r) >= 7:
		return false // commit hash
	}
	// "1", "1.2" and "^1" float; "1.2.3" and "v1.2.3" do not.
	r = strings.TrimPrefix(r, "v")
	if strings.ContainsAny(r, "^~*x") {
		return true
	}
	dots := strings.Count(r, ".")
	if dots >= 2 && r[0] >= '0' && r[0] <= '9' {
		return false
	}
	if r != "" && r[0] >= '0' && r[0] <= '9' {
		return true // "1" or "1.2": jsDelivr resolves these to the newest match
	}
	return true // any other name is a branch
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}
