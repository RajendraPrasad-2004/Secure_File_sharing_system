/* VaultShare client-side helpers. Pure convenience: ALL security checks are
   repeated on the server, so nothing here is trusted. Written without inline
   scripts so the strict Content-Security-Policy (script-src 'self') applies. */
document.addEventListener("DOMContentLoaded", function () {

  // Dismiss flash messages
  document.querySelectorAll(".flash-close").forEach(function (btn) {
    btn.addEventListener("click", function () { btn.parentElement.remove(); });
  });

  // Show / hide password
  document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.togglePassword);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // Password strength meter (registration)
  var pw = document.querySelector("input[data-strength]");
  if (pw) {
    var bar = document.getElementById(pw.dataset.strength);
    var text = document.getElementById("strength-text");
    pw.addEventListener("input", function () {
      var v = pw.value, score = 0;
      if (v.length >= 8) score++;
      if (v.length >= 12) score++;
      if (/[A-Z]/.test(v) && /[a-z]/.test(v)) score++;
      if (/\d/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v)) score++;
      var colors = ["#b3341f", "#b3341f", "#9a6408", "#9a6408", "#1f7a4d", "#1f7a4d"];
      var labels = ["Too weak", "Weak", "Fair", "Good", "Strong", "Very strong"];
      bar.style.width = (score * 20) + "%";
      bar.style.background = colors[score];
      text.textContent = v ? labels[score] : "At least 8 characters with a letter and a number.";
    });
  }

  // Confirm-password match hint
  var confirm = document.getElementById("confirm_password");
  if (confirm && pw) {
    var msg = document.getElementById("match-text");
    var check = function () { msg.hidden = !confirm.value || confirm.value === pw.value; };
    confirm.addEventListener("input", check);
    pw.addEventListener("input", check);
  }

  // Confirm destructive actions
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) { e.preventDefault(); }
    });
  });

  // Upload: early size check and file summary
  var fileInput = document.getElementById("file");
  if (fileInput && fileInput.dataset.maxBytes) {
    var info = document.getElementById("file-info");
    fileInput.addEventListener("change", function () {
      var f = fileInput.files[0];
      if (!f) { return; }
      var max = parseInt(fileInput.dataset.maxBytes, 10);
      if (f.size > max) {
        info.textContent = f.name + " is " + (f.size / 1048576).toFixed(1) + " MB, which is over the limit.";
        info.classList.add("error-text");
        fileInput.value = "";
      } else {
        info.textContent = f.name + " (" + (f.size / 1024).toFixed(1) + " KB) is ready to encrypt.";
        info.classList.remove("error-text");
      }
    });
  }
});
