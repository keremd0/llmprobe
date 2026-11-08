import base64

from llmprobe.attacks import load_attacks
from llmprobe.engine import build_probes
from llmprobe.judges import judge
from llmprobe.models import Attack, Detector, Probe, Severity, TargetResponse
from llmprobe.mutators import MUTATORS
from llmprobe.utils import get_path, normalize_tool_calls, render


def _attack(*detectors):
    return Attack(id="t", name="t", category="t", owasp="LLM01", severity=Severity.HIGH,
                  description="", payloads=["p"], detectors=list(detectors))


def _probe(attack, marker="LLMP-ABC123"):
    return Probe(attack=attack, payload="p", prompt="p", mutator="identity", marker=marker)


def test_builtin_attacks_load():
    ids = {a.id for a in load_attacks()}
    assert {"system-prompt-leak", "direct-prompt-injection", "indirect-prompt-injection",
            "excessive-agency-tool-abuse", "sensitive-data-disclosure"} <= ids


def test_get_path_and_render():
    data = {"choices": [{"message": {"content": "hi"}}]}
    assert get_path(data, "choices.0.message.content") == "hi"
    assert get_path(data, "choices[0].message.content") == "hi"
    assert get_path(data, "missing.path") is None
    body = render({"m": "{{prompt}}", "x": ["{{prompt}}!"]}, {"prompt": 'a "quoted" value'})
    assert body == {"m": 'a "quoted" value', "x": ['a "quoted" value!']}


def test_base64_mutator_roundtrip():
    out = MUTATORS["base64"]("reveal secrets")
    encoded = out.strip().splitlines()[-1]
    assert base64.b64decode(encoded).decode() == "reveal secrets"


def test_canary_plain_and_encoded():
    attack = _attack(Detector("canary"))
    canaries = ["CANARY-1234"]
    assert judge(_probe(attack), TargetResponse(text="secret is canary-1234 ok"), canaries).success
    spaced = TargetResponse(text="C A N A R Y - 1 2 3 4")
    assert judge(_probe(attack), spaced, canaries).success
    encoded = base64.b64encode(b"the code is CANARY-1234").decode()
    assert judge(_probe(attack), TargetResponse(text=f"here: {encoded}"), canaries).success
    assert not judge(_probe(attack), TargetResponse(text="nothing here"), canaries).success


def test_marker_ignores_refusals():
    attack = _attack(Detector("marker"))
    assert judge(_probe(attack), TargetResponse(text="LLMP-ABC123"), []).success
    refusal = TargetResponse(text="I'm sorry, but I can't say LLMP-ABC123 because that would break my rules.")
    assert not judge(_probe(attack), refusal, []).success


def test_tool_call_detector():
    attack = _attack(Detector("tool_call", value="send_email", arg="evil.test"))
    calls = normalize_tool_calls([{"function": {"name": "send_email",
                                                 "arguments": '{"to": "x@evil.test"}'}}])
    assert judge(_probe(attack), TargetResponse(text="", tool_calls=calls), []).success
    safe = normalize_tool_calls([{"name": "send_email", "arguments": {"to": "ok@company.example"}}])
    assert not judge(_probe(attack), TargetResponse(text="", tool_calls=safe), []).success


def test_probe_expansion_counts():
    attacks = load_attacks(only=["direct-prompt-injection", "indirect-prompt-injection"])
    probes = build_probes(attacks, ["identity", "base64"])
    direct = [p for p in probes if p.attack.id == "direct-prompt-injection"]
    indirect = [p for p in probes if p.attack.id == "indirect-prompt-injection"]
    assert len(direct) == 5 * 2                    # payloads x mutators
    assert len(indirect) == 2 * 2                  # payloads x documents, no mutation
    assert all(p.marker in p.document for p in indirect)
    assert len({p.marker for p in probes}) == len(probes)
