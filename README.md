# Ollama Security Research

This repository contains technical analysis, proof-of-concept demonstrations, and reproduction material for multiple security vulnerabilities identified in Ollama.

The findings documented here focus on denial-of-service conditions caused by improper handling of untrusted model data during model import and conversion.

---

## Findings

### 1. GGUF String Length Panic

**Location**

```text
gguf-string-panic/
```

**Summary**

A malformed GGUF file can trigger a runtime panic through an attacker-controlled string length field.

The parser reads an untrusted 64-bit length value and uses it directly during memory allocation without sufficient bounds validation.

This results in:

```text
panic: runtime error: makeslice: len out of range
```

leading to immediate service termination.

**Impact**

- Remote Denial of Service
- Service Crash
- Complete Loss of Availability

---

### 2. Resource Exhaustion via Unbounded `vocab_size`

**Location**

```text
vocabsize-resource-exhaustion/
```

**Summary**

The model conversion pipeline accepts an attacker-controlled `vocab_size` value from `config.json` and uses it to drive vocabulary padding operations.

Because no upper bound is enforced, an attacker can force excessive memory allocations and CPU consumption.

This may result in:

- 100% CPU utilization
- Memory exhaustion
- Swap exhaustion
- OOM termination
- Service unavailability

**Impact**

- Remote Denial of Service
- Resource Exhaustion
- Host Instability

---

## Repository Structure

```text
ollama-security-research/
│
├── README.md
│
├── gguf-string-panic/
│   ├── README.md
│   └── exploit.py
│
└── vocabsize-resource-exhaustion/
    ├── README.md
    └── exploit.py
```

---

## Disclosure

The findings contained in this repository were originally reported through coordinated disclosure channels.

The repository serves as a technical reference for researchers, defenders, and developers interested in understanding the root causes, impact, and exploitation paths of these vulnerabilities.

---

## Researcher

**Regaan**

- GitHub: https://github.com/regaan
- Website: https://rothackers.com
- ORCID: https://orcid.org/0009-0006-3683-7824

---

## Disclaimer

This repository is intended for educational, defensive, and research purposes only.

Do not test against systems you do not own or have explicit authorization to assess.
