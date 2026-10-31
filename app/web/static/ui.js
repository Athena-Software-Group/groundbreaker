/* Small page behaviours, kept out of the templates so the CSP needs no inline script. */
(function () {
  const copy = document.getElementById("copy-md");
  if (copy) {
    copy.addEventListener("click", () => {
      navigator.clipboard.writeText(document.getElementById("md").textContent)
        .then(() => { copy.textContent = "Copied"; setTimeout(() => { copy.textContent = "Copy Markdown"; }, 1500); });
    });
  }
})();
