#!/bin/bash
set -e
mkdir -p eval/results

echo "================================================================================"
echo "COMPLETE EVALUATION WORKFLOW"
echo "================================================================================"
echo ""

echo "1. LOCAL ATTACKS (WITHOUT PROXY - Vulnerable Baseline)"
echo "────────────────────────────────────────────────────────────────────────────────"
UPSTREAM_MODE=local python3 eval/attack_runner.py local_direct 2>&1 | tail -20
echo ""

echo "2. LOCAL ATTACKS (WITH PROXY - DZT Protected)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
UPSTREAM_MODE=local python3 eval/attack_runner.py local_proxy 2>&1 | tail -20
echo ""

echo "3. GITHUB ATTACKS (WITHOUT PROXY - Vulnerable Baseline)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
UPSTREAM_MODE=github python3 eval/attack_runner.py github_direct 2>&1 | tail -20
echo ""

echo "4. GITHUB ATTACKS (WITH PROXY - DZT Protected)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
UPSTREAM_MODE=github python3 eval/attack_runner.py github_proxy 2>&1 | tail -20
echo ""

echo "5. BENIGN TEST (False Positive Rate - Local)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
UPSTREAM_MODE=local python3 eval/benign_test.py 2>&1 | tail -20
echo ""

echo "6. BENIGN TEST (False Positive Rate - GitHub)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
UPSTREAM_MODE=github python3 eval/benign_test.py 2>&1 | tail -20
echo ""

echo "7. LATENCY BENCHMARK (Local - Direct vs Proxy Overhead)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
python3 eval/latency_benchmark.py 2>&1 | tail -20
echo ""

echo "8. LATENCY BENCHMARK (GitHub - Direct vs Proxy Overhead)"
echo "────────────────────────────────────────────────────────────────────────────────"
sleep 2
python3 eval/latency_benchmark_github.py 2>&1 | tail -20
echo ""

echo "9. FINAL REPORT GENERATION"
echo "────────────────────────────────────────────────────────────────────────────────"
python3 eval/generate_tables.py 2>&1 | tail -50
echo ""
echo "================================================================================"
echo "✅ ALL TESTS COMPLETE"
echo "================================================================================"
