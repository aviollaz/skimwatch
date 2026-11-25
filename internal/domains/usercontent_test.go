package domains

import "testing"

func TestParseUserCode(t *testing.T) {
	cases := []struct {
		url              string
		ok               bool
		service, account string
		mutable          bool
		fake             string
	}{
		// The PaperCut loader: a personal repo on a moving branch, named after jQuery.
		{"https://cdn.jsdelivr.net/gh/fs82g9omml/alianet@main/jQuery.1.3.1.js", true, "github", "fs82g9omml/alianet", true, "jquery"},
		{"https://cdn.jsdelivr.net/gh/jquery/jquery@3.7.1/dist/jquery.min.js", true, "github", "jquery/jquery", false, ""},
		{"https://cdn.jsdelivr.net/gh/someone/widgets@4f2a9c1/w.js", true, "github", "someone/widgets", false, ""},
		{"https://cdn.jsdelivr.net/gh/someone/widgets/w.js", true, "github", "someone/widgets", true, ""},
		{"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js", true, "npm", "jquery", false, ""},
		{"https://cdn.jsdelivr.net/npm/@mercadopago/sdk-js@0.0.3/dist/index.js", true, "npm", "@mercadopago/sdk-js", false, ""},
		{"https://unpkg.com/lodash", true, "npm", "lodash", true, ""},
		{"https://unpkg.com/some-pkg@latest/analytics.js", true, "npm", "some-pkg", true, "analytics"},
		{"https://raw.githubusercontent.com/u/r/master/x.js", true, "github", "u/r", true, ""},
		{"https://someone.github.io/lib/gtag.js", true, "github", "someone/lib", true, "gtag"},
		{"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", false, "", "", false, ""},
		{"https://www.googletagmanager.com/gtm.js?id=GTM-X", false, "", "", false, ""},
	}
	for _, c := range cases {
		uc, ok := ParseUserCode(c.url)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.url, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if uc.Service != c.service || uc.Account() != c.account || uc.Mutable != c.mutable || uc.ImpersonatedLibrary() != c.fake {
			t.Errorf("%s: got %s %s mutable=%v fake=%q", c.url, uc.Service, uc.Account(), uc.Mutable, uc.ImpersonatedLibrary())
		}
	}
}
