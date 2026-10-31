// Ordinary store code: analytics, cart updates, form validation.
(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});
var f=d.getElementsByTagName(s)[0],j=d.createElement(s);j.async=true;
j.src='https://www.googletagmanager.com/gtm.js?id='+i;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-XXXX');
document.querySelector("#newsletter").addEventListener("submit", function(e){
  e.preventDefault();
  fetch("/api/newsletter", {method: "POST", body: new FormData(e.target)});
});
function addToCart(sku){ return fetch("/api/cart", {method:"POST", body: JSON.stringify({sku: sku})}); }
