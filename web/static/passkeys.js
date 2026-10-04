/* Passkey (WebAuthn) glue. WebAuthn can only run in the browser, so this is the
   one place client JS talks to the ceremony endpoints. It submits a real form
   on completion, so the server renders redirects/recovery codes normally and
   the no-JS path still has the password form as a fallback.

   Base64url <-> ArrayBuffer conversion is the standard WebAuthn JSON bridge:
   the server emits/expects base64url strings, the browser API wants buffers. */
(function () {
  if (window.__ccPasskeys) return;
  window.__ccPasskeys = true;

  function b64urlToBytes(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    var pad = s.length % 4;
    if (pad) s += "====".slice(0, 4 - pad);
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeCreation(pk) {
    pk.challenge = b64urlToBytes(pk.challenge);
    if (pk.user && pk.user.id) pk.user.id = b64urlToBytes(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBytes(c.id); });
    return pk;
  }

  function decodeRequest(pk) {
    pk.challenge = b64urlToBytes(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64urlToBytes(c.id); });
    return pk;
  }

  function encodeAttestation(cred) {
    var r = cred.response;
    var out = {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        attestationObject: bytesToB64url(r.attestationObject)
      }
    };
    if (r.getTransports) out.response.transports = r.getTransports();
    return out;
  }

  function encodeAssertion(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        authenticatorData: bytesToB64url(r.authenticatorData),
        signature: bytesToB64url(r.signature),
        userHandle: r.userHandle ? bytesToB64url(r.userHandle) : null
      }
    };
  }

  function showError(msg) {
    var el = document.querySelector("[data-passkey-error]");
    if (el) {
      el.textContent = msg;
      el.hidden = false;
    }
  }

  function csrfToken(scope) {
    var el = (scope || document).querySelector('input[name="csrf_token"]');
    return el ? el.value : "";
  }

  function postJSON(url, payload, csrf) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" },
      body: JSON.stringify(payload || {})
    });
  }

  function unsupported() {
    return !(window.PublicKeyCredential && navigator.credentials);
  }

  async function passkeyLogin() {
    var form = document.getElementById("passkey-login-form");
    if (!form) return;
    if (unsupported()) { showError("This browser does not support passkeys."); return; }
    var resp;
    try {
      resp = await postJSON("/login/passkey/begin", {}, csrfToken(form));
    } catch (e) { showError("Could not reach the server."); return; }
    if (!resp.ok) { showError("Passkey sign-in is unavailable. Use the password form."); return; }
    var options = await resp.json();
    var cred;
    try {
      cred = await navigator.credentials.get({ publicKey: decodeRequest(options.publicKey) });
    } catch (e) { showError("Passkey sign-in was cancelled."); return; }
    form.querySelector('[name="credential"]').value = JSON.stringify(encodeAssertion(cred));
    form.submit();
  }

  async function passkeyRegister(btn) {
    if (unsupported()) { showError("This browser does not support passkeys."); return; }
    var beginURL = btn.getAttribute("data-begin-url");
    var finish = document.getElementById(btn.getAttribute("data-finish-form"));
    if (!beginURL || !finish) return;
    var nameEl = document.getElementById(btn.getAttribute("data-name-input") || "");
    var fieldsID = btn.getAttribute("data-fields");
    var addForm = fieldsID ? document.getElementById(fieldsID) : btn.closest("form");
    var payload = {};
    if (nameEl && nameEl.value.trim()) payload.name = nameEl.value.trim();
    if (addForm) {
      var pw = addForm.querySelector('[name="password"]');
      var code = addForm.querySelector('[name="code"]');
      if (pw) payload.password = pw.value;
      if (code) payload.code = code.value;
      if (!payload.name) {
        var label = addForm.querySelector('[name="label"]');
        if (label && label.value.trim()) payload.name = label.value.trim();
      }
    }
    var resp;
    try {
      resp = await postJSON(beginURL, payload, csrfToken(finish));
    } catch (e) { showError("Could not reach the server."); return; }
    if (!resp.ok) {
      var msg = "Could not start passkey registration.";
      try { var body = await resp.json(); if (body.error) msg = body.error; } catch (e) {}
      showError(msg);
      return;
    }
    var options = await resp.json();
    var cred;
    try {
      cred = await navigator.credentials.create({ publicKey: decodeCreation(options.publicKey) });
    } catch (e) { showError("Passkey registration was cancelled."); return; }
    finish.querySelector('[name="credential"]').value = JSON.stringify(encodeAttestation(cred));
    var nameField = finish.querySelector('[name="name"]');
    if (nameField && payload.name) nameField.value = payload.name;
    finish.submit();
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || typeof target.closest !== "function") return;
    var loginBtn = target.closest("[data-passkey-login]");
    if (loginBtn) { event.preventDefault(); passkeyLogin(loginBtn); return; }
    var regBtn = target.closest("[data-passkey-register]");
    if (regBtn) { event.preventDefault(); passkeyRegister(regBtn); }
  });
})();
