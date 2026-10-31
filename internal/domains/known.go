package domains

// Well-known providers whose scripts appear on most stores. They are trusted by the
// "sends data to an outside host" rules, so a store using Google Analytics is not flagged,
// and they are the reference list for look-alike detection: attackers register names
// like "google-analytlcs.com" precisely because these are expected on every page.
var KnownGood = []string{
	// Analytics and tag managers
	"google-analytics.com", "googletagmanager.com", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "ggpht.com",
	"googleadservices.com", "doubleclick.net", "googlesyndication.com", "analytics.google.com",
	"facebook.net", "facebook.com", "connect.facebook.net", "hotjar.com", "clarity.ms",
	"segment.com", "segment.io", "mixpanel.com", "amplitude.com", "tiktok.com", "bing.com",
	"criteo.com", "criteo.net", "taboola.com", "outbrain.com", "linkedin.com", "licdn.com",
	// CDNs and libraries
	"cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "jquery.com",
	"bootstrapcdn.com",
	// Shared hosting like cloudfront.net or akamaized.net is deliberately absent: anyone can
	// serve files from it, so a store that uses it should allowlist its own subdomain.
	"fontawesome.com", "typekit.net",
	// Payments and commerce platforms common in Argentina and LatAm
	"mercadopago.com", "mercadopago.com.ar", "mercadolibre.com", "mlstatic.com", "stripe.com", "stripe.network",
	"paypal.com", "paypalobjects.com", "decidir.com", "payway.com.ar", "todopago.com.ar",
	"vtex.com", "vtex.com.br", "vtexassets.com", "vteximg.com.br", "vtexcommercestable.com.br",
	"myvtex.com", "shopify.com", "shopifycdn.com", "myshopify.com", "tiendanube.com", "nuvemshop.com.br",
	"magento.com", "adobe.com", "adobedtm.com",
	// Monitoring, chat and consent
	"sentry.io", "sentry-cdn.com", "newrelic.com", "nr-data.net", "datadoghq.com", "browser-intake-datadoghq.com",
	"zendesk.com", "zdassets.com", "intercom.io", "intercomcdn.com", "onetrust.com", "cookielaw.org",
	"recaptcha.net", "hcaptcha.com", "youtube.com", "ytimg.com", "vimeo.com", "whatsapp.com", "wa.me",
}

var knownGoodSet = func() map[string]bool {
	m := make(map[string]bool, len(KnownGood))
	for _, d := range KnownGood {
		m[Registrable(d)] = true
	}
	return m
}()

// IsKnownGood reports whether a host belongs to a widely used, legitimate provider.
func IsKnownGood(host string) bool { return knownGoodSet[Registrable(host)] }
