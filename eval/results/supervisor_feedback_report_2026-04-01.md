# Supervisor Feedback Report

Date: 2026-04-01
Project: Decentralized Zero-Trust Proxy for MCP
Repository scope: capstone-dzt-proxy-main

## 1. Executive Summary
The project is in a strong validation state. The current implementation demonstrates complete blocking of tested attack sets in both local and GitHub scenarios while preserving benign traffic in the recorded campaign. The evidence supports a security-first evaluation framing: preliminary demonstration results are separated from formal evaluation, and the final assessment combines security effectiveness, accuracy support metrics, and performance overhead.

## 2. What Was Updated
The reporting pipeline has been structured into two distinct sections to avoid overstating early outcomes:

- Section 5.4 is explicitly labeled as preliminary demonstration evidence.
- Section 5.5 is structured as formal evaluation with metric definitions, evaluation tables, references, and reproducibility notes.

Implementation evidence:
- Section split and intent: [eval/generate_tables.py](../generate_tables.py#L3)
- Section 5.4 preliminary framing: [eval/generate_tables.py](../generate_tables.py#L152)
- Section 5.5 formal evaluation block: [eval/generate_tables.py](../generate_tables.py#L202)
- Generated output file used for reporting: [eval/results/capstone_tables.txt](capstone_tables.txt#L1)

## 3. Current Update Numbers (From Latest Generated Tables)
Source: [eval/results/capstone_tables.txt](capstone_tables.txt#L46)

### 3.1 Demonstration (Section 5.4)
- Local secured demonstration: ABR 100.0 percent (11/11 blocked), ASR 0.0 percent.
- GitHub secured demonstration: ABR 100.0 percent (12/12 blocked), ASR 0.0 percent.

Evidence lines:
- [eval/results/capstone_tables.txt](capstone_tables.txt#L8)
- [eval/results/capstone_tables.txt](capstone_tables.txt#L9)

### 3.2 Security Effectiveness (Section 5.5A)
- Local: ASR without proxy 66.7 percent, ASR with proxy 0.0 percent, ABR with proxy 100.0 percent.
- GitHub: ASR without proxy 88.9 percent, ASR with proxy 0.0 percent, ABR with proxy 100.0 percent.

Evidence lines:
- [eval/results/capstone_tables.txt](capstone_tables.txt#L50)
- [eval/results/capstone_tables.txt](capstone_tables.txt#L51)

### 3.3 Accuracy Support Metrics (Section 5.5B)
- Local benign: FP 0/100, FP rate 0.0 percent; FN 0/11, FN rate 0.0 percent.
- GitHub benign plus attacks: FP 0/100, FP rate 0.0 percent; FN 0/12, FN rate 0.0 percent.

Evidence lines:
- [eval/results/capstone_tables.txt](capstone_tables.txt#L60)
- [eval/results/capstone_tables.txt](capstone_tables.txt#L61)

### 3.4 Performance Metrics (Section 5.5C)
- Local:
  - Average direct latency: 1.9 ms
  - Average proxy latency: 34.5 ms
  - Average overhead: 32.5 ms
  - P95 direct: 2.7 ms
  - P95 proxy: 42.5 ms
  - P95 overhead: 39.9 ms
- GitHub:
  - Average direct latency: 763.1 ms
  - Average proxy latency: 773.2 ms
  - Average overhead: 10.2 ms
  - P95 direct: 802.7 ms
  - P95 proxy: 804.2 ms
  - P95 overhead: 1.4 ms

Evidence lines:
- [eval/results/capstone_tables.txt](capstone_tables.txt#L70)
- [eval/results/capstone_tables.txt](capstone_tables.txt#L71)

### 3.5 Additional Diagnostic Finding (Executed 2026-04-01)
A supplementary GitHub latency rerun with transport decomposition was conducted to contextualize the elevated absolute latency observed in the GitHub environment.

- Command executed: `python3 eval/latency_benchmark_github.py 5`
- Output artifact: [eval/results/latency_benchmark_github_1775061888.json](latency_benchmark_github_1775061888.json)
- Mean latency: direct 845.1 ms, proxy 807.5 ms, overhead -37.6 ms.
- P95 latency: direct 925.5 ms, proxy 856.0 ms, overhead -69.5 ms.

Single-call diagnostics from this run indicated that:
- Direct total latency was 786.8 ms, direct response elapsed time was 786.3 ms, and client overhead was 0.5 ms.
- Proxy JWT mint time was 1.07 ms, proxy total latency was 829.1 ms, proxy response elapsed time was 828.4 ms, and client overhead was 0.7 ms.

Curl transport snapshot for the direct GitHub request:
- DNS lookup: 2.3 ms
- TCP connection: 210.1 ms
- TLS handshake: 426.7 ms
- Time to first byte: 780.5 ms
- Total: 781.1 ms

Interpretation:
- The dominant contribution arises from network transit and remote service execution, particularly connection establishment and TLS negotiation.
- Local proxy and security-processing overhead remains small relative to end-to-end GitHub latency.
- Accordingly, overhead computed as proxy latency minus direct latency is the most informative proxy-efficiency indicator for this environment.

## 4. Test Runs Included in This Report
### 4.1 Unit and Integration Test Suite (Executed)
Command executed:
- PYTHONPATH=. python -m pytest tests/ -v

Result:
- 93 collected
- 93 passed
- 0 failed
- Runtime: 1.62 seconds

Coverage areas represented by passing suites include JWT handling, DID resolution, nonce replay protection, policy enforcement, rate limiting, tool hashing integrity, and SSE parsing.

Primary test files:
- [tests/test_core.py](../../tests/test_core.py)
- [tests/test_did_resolver.py](../../tests/test_did_resolver.py)
- [tests/test_jwt_utils.py](../../tests/test_jwt_utils.py)
- [tests/test_nonce_store.py](../../tests/test_nonce_store.py)
- [tests/test_policy.py](../../tests/test_policy.py)
- [tests/test_rate_limiter.py](../../tests/test_rate_limiter.py)
- [tests/test_tool_registry.py](../../tests/test_tool_registry.py)

### 4.2 Evaluation Campaign Artifacts (Referenced by Generator)
The report generator recorded the artifact set used to compute current numbers:
- Local direct attacks: eval/results/attack_run_local_direct_1774697860.json
- Local proxy attacks: eval/results/attack_run_local_proxy_1774697881.json
- GitHub direct attacks: eval/results/attack_run_github_direct_1775041688.json
- GitHub proxy attacks: eval/results/attack_run_github_proxy_1774698115.json
- Local benign test: eval/results/benign_test_1774697394.json
- GitHub benign test: eval/results/benign_test_1774694873.json
- Local latency benchmark: eval/results/latency_benchmark_1774698767.json
- GitHub latency benchmark: eval/results/latency_benchmark_github_1774698805.json
- GitHub latency diagnostic (with breakdown): eval/results/latency_benchmark_github_1775061888.json

Evidence lines:
- [eval/results/capstone_tables.txt](capstone_tables.txt#L113)
- [eval/results/capstone_tables.txt](capstone_tables.txt#L125)

## 5. Process Explanation: How the Code Works
### 5.1 Reporting Workflow
1. Raw runs are produced by attack, benign, and latency scripts and saved as JSON in eval/results.
2. The generator loads the latest artifacts and computes summary metrics.
3. It writes two report sections:
- Section 5.4 for preliminary demonstration.
- Section 5.5 for formal evaluation and reproducibility.

Implementation references:
- Latest-file discovery and loading: [eval/generate_tables.py](../generate_tables.py#L26)
- Attack summarization and ASR/ABR formulas: [eval/generate_tables.py](../generate_tables.py#L56)
- Section 5.4 rendering: [eval/generate_tables.py](../generate_tables.py#L149)
- Section 5.5 rendering: [eval/generate_tables.py](../generate_tables.py#L189)
- Output write path: [eval/generate_tables.py](../generate_tables.py#L474)

### 5.2 Metric Calculations Used
Security:
- ASR = successful attacks / total attacks
- ABR = blocked attacks / total attacks

Formula implementation:
- [eval/generate_tables.py](../generate_tables.py#L60)
- [eval/generate_tables.py](../generate_tables.py#L78)
- [eval/generate_tables.py](../generate_tables.py#L79)

Accuracy support:
- FP comes from benign failures.
- FN equals successful attacks under proxy in the attack run.

Implementation:
- Benign FP rate computation: [eval/benign_test.py](../benign_test.py#L125)
- FN extraction in report assembly: [eval/generate_tables.py](../generate_tables.py#L268)

Performance:
- Average latency, p95 latency, and overhead where overhead equals proxy minus direct.

Implementation:
- Local benchmark calculations: [eval/latency_benchmark.py](../latency_benchmark.py#L166)
- GitHub benchmark calculations: [eval/latency_benchmark_github.py](../latency_benchmark_github.py#L151)
- p95 percentile function: [eval/latency_benchmark.py](../latency_benchmark.py#L98)

### 5.3 Security Pipeline Context
The proxy is implemented as a FastAPI service and enforces an 8-step verification pipeline before forwarding calls.

Implementation and architecture references:
- Proxy app and FastAPI setup: [dzt_proxy/app.py](../../dzt_proxy/app.py#L46)
- README architecture and verification flow: [README.md](../../README.md#L9)

## 6. Professional Assessment for Supervisor
### Strengths
- Clear and correct evaluation framing (demonstration versus formal evaluation).
- Strong security outcomes on the current attack set (ABR 100 percent, ASR 0 percent in proxy mode for both environments).
- No false positives observed in the recorded benign campaign.
- Low incremental proxy overhead in GitHub mode relative to remote baseline, and acceptable local overhead for a security gate.
- Full unit and integration suite currently passing (93 out of 93).

### Risks and Caveats
- Current demonstration and evaluation are bounded to the tested attack catalog and traffic profile.
- Some supplementary ML comparison rows remain placeholders by design and are not required for rule-based security claims.
- External-network variability affects absolute GitHub latencies; overhead is the more reliable performance indicator.

## 7. Recommended Next Actions
1. Freeze one final campaign run set and archive all referenced JSON artifacts under a final tag.
2. Include this report and the generated Section 5.4/5.5 tables as thesis appendices.
3. Expand attack diversity and load levels for final robustness claims.
4. Optionally add CI execution of pytest and table generation for automatic evidence refresh.

## 8. External Standards and References Used
- OWASP Top 10
- NIST SP 800-53 Rev. 5
- Google FP/FN primer
- AWS p95 and latency engineering note

Anchors are included in:
- [eval/results/capstone_tables.txt](capstone_tables.txt#L107)
