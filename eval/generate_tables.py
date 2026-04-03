#!/usr/bin/env python3
"""
Report Table Generator -- Produces Section 5.4 and 5.5 text blocks.

The generator intentionally separates:
    - Section 5.4 Demonstration: preliminary experimental results
    - Section 5.5 Evaluation: formal metric definitions + tables + placeholders

This avoids presenting early local runs as final conclusions and keeps
the report aligned with security-system evaluation practice.

Usage:
        python eval/generate_tables.py
"""

import os
import sys
import json
import glob
import time
import argparse
from pathlib import Path
from typing import Dict, Optional


def find_latest(pattern: str) -> str:
    files = sorted(glob.glob(pattern))
    return files[-1] if files else ""


def find_latest_benign(mode: str) -> str:
    """Find the latest benign result for a given mode (local or github)."""
    files = sorted(glob.glob("eval/results/benign_test_*.json"), reverse=True)
    for path in files:
        data = load(path)
        if data.get("mode", "local").lower() == mode:
            return path
    return ""


def load(path: str) -> dict:
    if not path or not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text())


def is_attack_result(name: str) -> bool:
    n = name.lower()
    if "valid request" in n:
        return False
    if "replay (1st" in n or "replay (1st use" in n:
        return False
    return True


def summarize_attacks(data: dict) -> Optional[Dict[str, float]]:
    """
    Summarize an attack-run JSON into security metrics.

    ASR = successful_attacks / total_attacks
    ABR = blocked_attacks / total_attacks
    """
    if not data:
        return None

    attacks = [r for r in data.get("results", []) if is_attack_result(r.get("name", ""))]
    total = len(attacks)
    if total == 0:
        return None

    blocked = sum(1 for r in attacks if r.get("blocked", False))
    succeeded = total - blocked

    return {
        "total": total,
        "blocked": blocked,
        "succeeded": succeeded,
        "asr_pct": round((succeeded / total) * 100.0, 1),
        "abr_pct": round((blocked / total) * 100.0, 1),
    }


def format_pct(value: Optional[float]) -> str:
    if value is None:
        return "TBD"
    return f"{value:.1f}%"


def format_ratio(n: Optional[int], d: Optional[int]) -> str:
    if n is None or d is None:
        return "TBD"
    return f"{n}/{d}"


def calculate_ml_metrics(attack_data: dict, benign_data: dict) -> Optional[Dict[str, float]]:
    """
    Calculate advanced ML classification metrics.
    
    TP (True Positive)  = Blocked attacks (correctly identified threats)
    FP (False Positive) = Benign requests blocked (incorrectly flagged)
    FN (False Negative) = Successful attacks (threats not detected)
    TN (True Negative)  = Benign requests allowed (correct non-threats)
    
    Precision = TP / (TP + FP)   — of all blocked requests, how many were actual attacks?
    Recall    = TP / (TP + FN)   — of all actual attacks, how many did we catch?
    F1 Score  = 2 * (Precision * Recall) / (Precision + Recall) — harmonic mean
    
    Note: attack_run includes both benign-looking requests (valid, 1st replay) and attacks.
    We count benign-in-attack-run + separate benign_test results as TN contributions.
    """
    if not attack_data or not benign_data:
        return None
    
    # From attack run: separate benign (valid request, 1st replay) from attacks
    all_results = attack_data.get("results", [])
    benign_in_attack_run = [r for r in all_results if not is_attack_result(r.get("name", ""))]
    actual_attacks = [r for r in all_results if is_attack_result(r.get("name", ""))]
    
    # TP: Blocked attacks
    tp = sum(1 for r in actual_attacks if r.get("blocked", False))
    
    # FN: Successful attacks (attacks that got through)
    fn = len(actual_attacks) - tp
    
    # FP: Benign requests blocked (from separate benign test)
    fp = benign_data.get("failures", 0)
    
    # TN: Benign requests allowed = benign within attack run (if allowed) + benign_test allowed
    benign_allowed_in_attack_run = sum(1 for r in benign_in_attack_run if not r.get("blocked", False))
    total_benign_test = benign_data.get("total_calls", 0)
    tn = benign_allowed_in_attack_run + (total_benign_test - fp)
    
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision * 100.0, 1),
        "recall": round(recall * 100.0, 1),
        "f1": round(f1 * 100.0, 1),
    }


def section_54_demonstration(local_proxy: dict, github_proxy: dict) -> str:
    """Section 5.4 -- Demonstration (preliminary results only)."""
    lines = []
    lines.append("SECTION 5.4 -- Demonstration (Preliminary Experimental Results)")
    lines.append("=" * 78)
    lines.append("")
    lines.append("  The following values are preliminary experimental results")
    lines.append("  (initial validation results), not final evaluation conclusions.")
    lines.append("  They are provided only to demonstrate feasibility of the DZT pipeline.")
    lines.append("")

    local_s = summarize_attacks(local_proxy)
    github_s = summarize_attacks(github_proxy)

    if local_s:
        lines.append(
            "  Local secured demonstration: "
            f"ABR={format_pct(local_s['abr_pct'])} ({local_s['blocked']}/{local_s['total']} blocked), "
            f"ASR={format_pct(local_s['asr_pct'])}."
        )
    else:
        lines.append("  Local secured demonstration: TBD (run local proxy attacks).")

    if github_s:
        lines.append(
            "  GitHub secured demonstration: "
            f"ABR={format_pct(github_s['abr_pct'])} ({github_s['blocked']}/{github_s['total']} blocked), "
            f"ASR={format_pct(github_s['asr_pct'])}."
        )
    else:
        lines.append("  GitHub secured demonstration: TBD (run github proxy attacks).")

    lines.append("")
    lines.append("  Final claims will be reported in Section 5.5 after full testing")
    lines.append("  and controlled direct-vs-proxy comparisons in real/GitHub conditions.")
    lines.append("")

    return "\n".join(lines)


def section_55_evaluation(
    local_direct: dict,
    local_proxy: dict,
    github_direct: dict,
    github_proxy: dict,
    benign_local: dict,
    benign_github: dict,
    latency_local: dict,
    latency_github: dict,
    source_paths: Dict[str, str],
) -> str:
    """Section 5.5 -- Formal evaluation structure and tables."""
    lines = []
    lines.append("SECTION 5.5 -- Evaluation")
    lines.append("=" * 78)
    lines.append("")
    lines.append("  Metrics and Measurement Plan")
    lines.append("  - Security Effectiveness (Primary):")
    lines.append("      ASR = Successful attacks / Total attacks")
    lines.append("      ABR = Blocked attacks / Total attacks")
    lines.append("  - Accuracy (Support):")
    lines.append("      FP = Legitimate requests incorrectly blocked")
    lines.append("      FN = Attack requests not blocked")
    lines.append("  - Performance (Critical):")
    lines.append("      Average latency (ms), p95 latency (ms), and latency overhead vs baseline")
    lines.append("      Latency overhead = Proxy latency - Baseline MCP latency")
    lines.append("")
    lines.append("  Note: Accuracy/precision-only reporting is insufficient for a security")
    lines.append("  enforcement proxy; security effectiveness and latency must be included.")
    lines.append("")

    local_d = summarize_attacks(local_direct)
    local_p = summarize_attacks(local_proxy)

    lines.append("  TABLE 5.5F -- Attack-to-Control Mapping (Appendix-Ready)")
    lines.append("  " + "-" * 74)
    lines.append(f"  {'Attack Pattern':<32} {'Proxy Control':<22} {'Reference':<18}")
    lines.append("  " + "-" * 74)
    lines.append(f"  {'Replay (2nd/3rd use)':<32} {'Nonce replay_protection':<22} {'OWASP A07, NIST IA':<18}")
    lines.append(f"  {'No token / stolen PAT reuse':<32} {'token_presence + DID bind':<22} {'OWASP A07, NIST IA':<18}")
    lines.append(f"  {'Tampered/malformed JWT':<32} {'jwt_decode + signature_verification':<22} {'OWASP A08, NIST SI':<18}")
    lines.append(f"  {'Wrong audience / expired token':<32} {'audience_validation + token_expiry':<22} {'OWASP A05/A07, NIST IA':<18}")
    lines.append(f"  {'Tool mismatch (claim vs request)':<32} {'tool_binding':<22} {'OWASP A01, NIST AC':<18}")
    lines.append(f"  {'Tool poisoning (bad hash)':<32} {'tool_integrity':<22} {'OWASP A08, NIST SI-7':<18}")
    lines.append(f"  {'Policy bypass / unsafe tool':<32} {'policy_enforcement':<22} {'OWASP A01, NIST AC':<18}")
    lines.append(f"  {'Credential theft path access':<32} {'policy_enforcement':<22} {'OWASP A01, NIST AC':<18}")
    lines.append("  " + "-" * 74)
    lines.append("  Note: mappings are grounded in observed blocked_by stages in attack-run JSON outputs.")
    lines.append("")

    github_d = summarize_attacks(github_direct)
    github_p = summarize_attacks(github_proxy)

    lines.append("  TABLE 5.5A -- Security Effectiveness (Primary)")
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Environment':<12} {'ASR w/o Proxy':>14} {'ASR w/ Proxy':>13} {'ABR w/ Proxy':>13} {'Evidence':>16}"
    )
    lines.append("  " + "-" * 74)

    lines.append(
        f"  {'Local':<12} "
        f"{format_pct(local_d['asr_pct']) if local_d else 'TBD':>14} "
        f"{format_pct(local_p['asr_pct']) if local_p else 'TBD':>13} "
        f"{format_pct(local_p['abr_pct']) if local_p else 'TBD':>13} "
        f"{(format_ratio(local_p['blocked'], local_p['total']) + ' blocked') if local_p else 'pending full run':>16}"
    )
    lines.append(
        f"  {'GitHub':<12} "
        f"{format_pct(github_d['asr_pct']) if github_d else 'TBD':>14} "
        f"{format_pct(github_p['asr_pct']) if github_p else 'TBD':>13} "
        f"{format_pct(github_p['abr_pct']) if github_p else 'TBD':>13} "
        f"{(format_ratio(github_p['blocked'], github_p['total']) + ' blocked') if github_p else 'pending full run':>16}"
    )
    lines.append("  " + "-" * 74)
    lines.append("  Interpretation: ABR close to 100% and ASR close to 0% indicate strong")
    lines.append("  threat prevention for the evaluated attack set.")
    lines.append("")

    local_fn = local_p["succeeded"] if local_p else None
    github_fn = github_p["succeeded"] if github_p else None
    local_fn_rate = local_p["asr_pct"] if local_p else None
    github_fn_rate = github_p["asr_pct"] if github_p else None

    local_fp = benign_local.get("failures") if benign_local else None
    local_fp_total = benign_local.get("total_calls") if benign_local else None
    local_fp_rate = benign_local.get("false_positive_rate_pct") if benign_local else None

    github_fp = benign_github.get("failures") if benign_github else None
    github_fp_total = benign_github.get("total_calls") if benign_github else None
    github_fp_rate = benign_github.get("false_positive_rate_pct") if benign_github else None

    lines.append("  TABLE 5.5B -- Accuracy Metrics (Support)")
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Environment':<12} {'FP':>12} {'FP Rate':>10} {'FN':>12} {'FN Rate':>10} {'Notes':>14}"
    )
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Local':<12} "
        f"{format_ratio(local_fp, local_fp_total):>12} "
        f"{format_pct(float(local_fp_rate)) if local_fp_rate is not None else 'TBD':>10} "
        f"{format_ratio(local_fn, local_p['total']) if local_p else 'TBD':>12} "
        f"{format_pct(local_fn_rate):>10} "
        f"{'FP from benign test':>14}"
    )
    lines.append(
        f"  {'GitHub':<12} "
        f"{format_ratio(github_fp, github_fp_total):>12} "
        f"{format_pct(float(github_fp_rate)) if github_fp_rate is not None else 'TBD':>10} "
        f"{format_ratio(github_fn, github_p['total']) if github_p else 'TBD':>12} "
        f"{format_pct(github_fn_rate):>10} "
        f"{'from benign + attacks':>14}"
    )
    lines.append("  " + "-" * 74)
    lines.append("  Interpretation: FP/FN are support metrics for reliability; they must be")
    lines.append("  interpreted together with ABR/ASR for security systems.")
    lines.append("")

    d = latency_local.get("direct", {}) if latency_local else {}
    p = latency_local.get("proxy", {}) if latency_local else {}
    o = latency_local.get("overhead", {}) if latency_local else {}
    gd = latency_github.get("direct", {}) if latency_github else {}
    gp = latency_github.get("proxy", {}) if latency_github else {}
    go = latency_github.get("overhead", {}) if latency_github else {}

    lines.append("  TABLE 5.5C -- Performance Metrics (Critical)")
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Environment':<12} {'Avg Direct':>10} {'Avg Proxy':>10} {'Avg O/H':>10} {'P95 Direct':>10} {'P95 Proxy':>10} {'P95 O/H':>10}"
    )
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Local':<12} "
        f"{str(d.get('avg_ms', 'TBD')):>10} "
        f"{str(p.get('avg_ms', 'TBD')):>10} "
        f"{str(o.get('avg_ms', 'TBD')):>10} "
        f"{str(d.get('p95_ms', 'TBD')):>10} "
        f"{str(p.get('p95_ms', 'TBD')):>10} "
        f"{str(o.get('p95_ms', 'TBD')):>10}"
    )
    lines.append(
        f"  {'GitHub':<12} "
        f"{str(gd.get('avg_ms', 'TBD')):>10} "
        f"{str(gp.get('avg_ms', 'TBD')):>10} "
        f"{str(go.get('avg_ms', 'TBD')):>10} "
        f"{str(gd.get('p95_ms', 'TBD')):>10} "
        f"{str(gp.get('p95_ms', 'TBD')):>10} "
        f"{str(go.get('p95_ms', 'TBD')):>10}"
    )
    lines.append("  " + "-" * 74)
    lines.append("  Interpretation: latency overhead quantifies the operational cost of")
    lines.append("  zero-trust enforcement and should be evaluated against service SLOs.")
    lines.append("")

    # Advanced ML Classification Metrics
    lines.append("  TABLE 5.5D -- Advanced ML Classification Metrics (Supplementary)")
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Environment':<12} {'Precision':>12} {'Recall':>10} {'F1 Score':>10} {'TP':>8} {'FP':>8} {'FN':>8} {'TN':>8}"
    )
    lines.append("  " + "-" * 74)

    local_p_ml = calculate_ml_metrics(local_proxy, benign_local)
    github_p_ml = calculate_ml_metrics(github_proxy, benign_github)

    if local_p_ml:
        lines.append(
            f"  {'Local':<12} "
            f"{format_pct(local_p_ml['precision']):>12} "
            f"{format_pct(local_p_ml['recall']):>10} "
            f"{format_pct(local_p_ml['f1']):>10} "
            f"{local_p_ml['tp']:>8} "
            f"{local_p_ml['fp']:>8} "
            f"{local_p_ml['fn']:>8} "
            f"{local_p_ml['tn']:>8}"
        )
    else:
        lines.append(f"  {'Local':<12} {'TBD':>12} {'TBD':>10} {'TBD':>10} {'TBD':>8} {'TBD':>8} {'TBD':>8} {'TBD':>8}")

    if github_p_ml:
        lines.append(
            f"  {'GitHub':<12} "
            f"{format_pct(github_p_ml['precision']):>12} "
            f"{format_pct(github_p_ml['recall']):>10} "
            f"{format_pct(github_p_ml['f1']):>10} "
            f"{github_p_ml['tp']:>8} "
            f"{github_p_ml['fp']:>8} "
            f"{github_p_ml['fn']:>8} "
            f"{github_p_ml['tn']:>8}"
        )
    else:
        lines.append(f"  {'GitHub':<12} {'TBD':>12} {'TBD':>10} {'TBD':>10} {'TBD':>8} {'TBD':>8} {'TBD':>8} {'TBD':>8}")

    lines.append("  " + "-" * 74)
    lines.append("  Interpretation (ML Metrics):")
    lines.append("  - Precision: Of all requests blocked, what % were actual attacks? (not false alarms)")
    lines.append("  - Recall: Of all actual attacks, what % did we successfully catch?")
    lines.append("  - F1 Score: Harmonic mean of Precision & Recall (0-100, higher is better)")
    lines.append("  - TP/FP/FN/TN: Confusion matrix — raw counts for detailed analysis")
    lines.append("")
    lines.append("  Connection to Security Metrics:")
    lines.append("  - High Precision (close to 100%) + High Recall (close to 100%) + High F1 (close to 100%)")
    lines.append("    confirms that the proxy is both effective (catches attacks) and precise (no false alarms)")
    lines.append("")

    # ML comparison placeholders for future model integration
    lines.append("  TABLE 5.5E -- Rule vs ML Comparison (Supplementary)")
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Environment':<12} {'Setup':<12} {'ASR':>8} {'ABR':>8} {'FP Rate':>10} {'F1':>8} {'Status':>12}"
    )
    lines.append("  " + "-" * 74)
    lines.append(
        f"  {'Local':<12} {'Rule-only':<12} "
        f"{format_pct(local_p['asr_pct']) if local_p else 'TBD':>8} "
        f"{format_pct(local_p['abr_pct']) if local_p else 'TBD':>8} "
        f"{format_pct(float(local_fp_rate)) if local_fp_rate is not None else 'TBD':>10} "
        f"{format_pct(local_p_ml['f1']) if local_p_ml else 'TBD':>8} "
        f"{'measured':>12}"
    )
    lines.append(
        f"  {'Local':<12} {'Rule+ML':<12} {'TBD':>8} {'TBD':>8} {'TBD':>10} {'TBD':>8} {'pending run':>12}"
    )
    lines.append(
        f"  {'Local':<12} {'ML-only':<12} {'TBD':>8} {'TBD':>8} {'TBD':>10} {'TBD':>8} {'pending run':>12}"
    )
    lines.append(
        f"  {'GitHub':<12} {'Rule-only':<12} "
        f"{format_pct(github_p['asr_pct']) if github_p else 'TBD':>8} "
        f"{format_pct(github_p['abr_pct']) if github_p else 'TBD':>8} "
        f"{format_pct(float(github_fp_rate)) if github_fp_rate is not None else 'TBD':>10} "
        f"{format_pct(github_p_ml['f1']) if github_p_ml else 'TBD':>8} "
        f"{'measured':>12}"
    )
    lines.append(
        f"  {'GitHub':<12} {'Rule+ML':<12} {'TBD':>8} {'TBD':>8} {'TBD':>10} {'TBD':>8} {'pending run':>12}"
    )
    lines.append(
        f"  {'GitHub':<12} {'ML-only':<12} {'TBD':>8} {'TBD':>8} {'TBD':>10} {'TBD':>8} {'pending run':>12}"
    )
    lines.append("  " + "-" * 74)
    lines.append("  Interpretation: this table is a structured comparison scaffold for adding")
    lines.append("  a future learned model without changing the current security-first framework.")
    lines.append("")

    lines.append("  External reference anchors:")
    lines.append("  - OWASP Top 10: https://owasp.org/www-project-top-ten/")
    lines.append("  - NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final")
    lines.append("  - Accuracy/FP/FN primer: https://developers.google.com/machine-learning/crash-course/classification/accuracy-precision-recall")
    lines.append("  - Latency and p95 background: https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/")
    lines.append("")
    lines.append("  Reproducibility Notes")
    lines.append("  - Measurement date: " + time.strftime("%Y-%m-%d"))
    lines.append("  - Attack runs: ")
    lines.append("      local direct  : " + (source_paths.get("local_direct") or "N/A"))
    lines.append("      local proxy   : " + (source_paths.get("local_proxy") or "N/A"))
    lines.append("      github direct : " + (source_paths.get("github_direct") or "N/A"))
    lines.append("      github proxy  : " + (source_paths.get("github_proxy") or "N/A"))
    lines.append("  - Benign runs:")
    lines.append("      local         : " + (source_paths.get("benign_local") or "N/A"))
    lines.append("      github        : " + (source_paths.get("benign_github") or "N/A"))
    lines.append("  - Latency runs:")
    lines.append("      local         : " + (source_paths.get("latency_local") or "N/A"))
    lines.append("      github        : " + (source_paths.get("latency_github") or "N/A"))
    lines.append("  - Command set used for final campaign:")
    lines.append("      python3 eval/attack_runner.py local_direct")
    lines.append("      python3 eval/attack_runner.py local_proxy")
    lines.append("      python3 eval/attack_runner.py github_direct")
    lines.append("      python3 eval/attack_runner.py github_proxy")
    lines.append("      python3 eval/benign_test.py 100")
    lines.append("      python3 eval/latency_benchmark.py 30")
    lines.append("      python3 eval/latency_benchmark_github.py 20")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate Section 5.4 and 5.5 report blocks")
    parser.add_argument("--direct", default="")
    parser.add_argument("--proxy", default="")
    parser.add_argument("--benign", default="")
    parser.add_argument("--latency", default="")
    parser.add_argument("--latency-github", default="")
    parser.add_argument("--out", default="eval/results/capstone_tables.txt")
    args = parser.parse_args()

    local_direct_path = args.direct or find_latest("eval/results/attack_run_local_direct_*.json")
    local_proxy_path = args.proxy or find_latest("eval/results/attack_run_local_proxy_*.json")
    github_direct_path = find_latest("eval/results/attack_run_github_direct_*.json")
    github_proxy_path = find_latest("eval/results/attack_run_github_proxy_*.json")

    # If --benign is provided, use it as local benign for backward compatibility.
    benign_local_path = args.benign or find_latest_benign("local")
    benign_github_path = find_latest_benign("github")
    latency_path = args.latency or find_latest("eval/results/latency_benchmark_[0-9]*.json")
    latency_github_path = args.latency_github or find_latest("eval/results/latency_benchmark_github_*.json")

    local_direct = load(local_direct_path)
    local_proxy = load(local_proxy_path)
    github_direct = load(github_direct_path)
    github_proxy = load(github_proxy_path)
    benign_local = load(benign_local_path)
    benign_github = load(benign_github_path)
    latency_local = load(latency_path)
    latency_github = load(latency_github_path)

    print(f"\n{'='*78}")
    print(f"  CAPSTONE REPORT GENERATOR")
    print(f"{'='*78}")
    print(f"  Sources:")
    print(f"    Local direct attacks : {local_direct_path or '(not found -- run option 1)'}")
    print(f"    Local proxy attacks  : {local_proxy_path or '(not found -- run option 2)'}")
    print(f"    GitHub direct attacks: {github_direct_path or '(not found -- run option 3)'}")
    print(f"    GitHub proxy attacks : {github_proxy_path or '(not found -- run option 4)'}")
    print(f"    Benign local test    : {benign_local_path or '(not found -- run option 5 local)'}")
    print(f"    Benign GitHub test   : {benign_github_path or '(not found -- run benign with UPSTREAM_MODE=github)'}")
    print(f"    Latency local        : {latency_path or '(not found -- run option 6)'}")
    print(f"    Latency GitHub       : {latency_github_path or '(not found -- run eval/latency_benchmark_github.py)'}")
    print()

    output_lines = []

    s54 = section_54_demonstration(local_proxy, github_proxy)
    print(s54)
    output_lines.append(s54)

    s55 = section_55_evaluation(
        local_direct=local_direct,
        local_proxy=local_proxy,
        github_direct=github_direct,
        github_proxy=github_proxy,
        benign_local=benign_local,
        benign_github=benign_github,
        latency_local=latency_local,
        latency_github=latency_github,
        source_paths={
            "local_direct": local_direct_path,
            "local_proxy": local_proxy_path,
            "github_direct": github_direct_path,
            "github_proxy": github_proxy_path,
            "benign_local": benign_local_path,
            "benign_github": benign_github_path,
            "latency_local": latency_path,
            "latency_github": latency_github_path,
        },
    )
    print(s55)
    output_lines.append(s55)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(output_lines))
    print(f"  Tables saved: {out_path}\n")


if __name__ == "__main__":
    main()
