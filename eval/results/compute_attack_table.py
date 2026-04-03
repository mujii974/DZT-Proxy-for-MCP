#eval/results/compute_attack_table
import glob
import json
from pathlib import Path

# Map your run_all_attacks test names to the report categories (Table 2)
CATEGORY_MAP = {
    "Prompt Injection": [
        "ATTACK_tool_mismatch_token_vs_request",  # token says get_me but request calls other tool
        "ATTACK_tool_mismatch_token_vs_request",  # treat as prompt-injection style tool swap
    ],
    "Tool Poisoning": [
        "ATTACK_tool_hash_mismatch",
    ],
    "Session Hijacking": [
        "ATTACK_wrong_audience",
        "ATTACK_unknown_issuer_did",
    ],
    "RCE (Remote Code Execution)": [
        "ATTACK_disallowed_tool_run_cmd",
    ],
    "Replay": [
        "ATTACK_replay_second",
    ],
}

def load_latest_run_all_attacks():
    files = sorted(glob.glob("eval/out/run_all_attacks_*.json"))
    if not files:
        raise SystemExit("No eval/out/run_all_attacks_*.json found. Run: python eval/run_all_attacks.py")
    latest = files[-1]
    data = json.loads(Path(latest).read_text())
    return latest, data

def summarize_after_dzt(data):
    # Build dict {test_name: status_code}
    status = {}
    for t in data.get("tests", []):
        name = t.get("name")
        sc = t.get("status")
        if name and sc is not None:
            status[name] = int(sc)

    # For "After DZT", an attack is considered SUCCESSFULLY BLOCKED if status is 401/403 (or any 4xx)
    # NOTE: 500 means your infra is misconfigured (like missing GITHUB_PAT)
    results = {}
    for cat, tests in CATEGORY_MAP.items():
        seen = [status.get(x) for x in tests if x in status]
        if not seen:
            results[cat] = {"blocked": 0, "total": len(tests), "rate": None, "note": "missing tests in JSON"}
            continue
        blocked = sum(1 for sc in seen if 400 <= sc < 500)
        total = len(seen)
        rate = round((blocked / total) * 100.0, 2) if total else 0.0
        results[cat] = {"blocked": blocked, "total": total, "rate": rate}
    return results

def main():
    latest, data = load_latest_run_all_attacks()
    after = summarize_after_dzt(data)

    print("\n=== Using:", latest, "===\n")
    print("Table 2 (Attack Success Rate Evaluation)\n")
    print("Attack Type | Before DZT (Success Rate) | After DZT (Success Rate) | Notes")
    print("---|---:|---:|---")

    for cat in ["Prompt Injection", "Tool Poisoning", "Session Hijacking", "RCE (Remote Code Execution)", "Replay"]:
        a = after.get(cat, {})
        after_block_rate = a.get("rate", None)

        # In your report: "After DZT success rate" should mean "attack success" (should be 0%).
        # We measured BLOCKED %. So Attack Success After = 100 - Blocked%.
        if after_block_rate is None:
            after_attack_success = "N/A"
            note = a.get("note", "")
        else:
            after_attack_success = f"{round(100.0 - after_block_rate, 2)}%"
            note = f"blocked {after_block_rate}% ({a['blocked']}/{a['total']})"

        # For BEFORE DZT: if you run a truly insecure server, these will be close to 100%.
        # If you haven't measured it yet, keep it as TBFI.
        before_attack_success = "TBFI"

        print(f"{cat} | {before_attack_success} | {after_attack_success} | {note}")

    print("\nNOTE:")
    print("- If you see 500 in run_all_attacks, fix env (GITHUB_PAT) and rerun.")
    print("- 'Before DZT' requires running baseline server without proxy defenses (measure separately).")

if __name__ == "__main__":
    main()