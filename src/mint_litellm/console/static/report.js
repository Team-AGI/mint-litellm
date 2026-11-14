document.querySelectorAll("[data-print]").forEach(function (button) {
  button.addEventListener("click", function () {
    window.print();
  });
});
