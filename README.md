# anonymize

> **DISCLAIMER — PLEASE READ BEFORE USE**
>
> This project was **built with the assistance of AI** (Claude, by Anthropic).
>
> It **may contain security vulnerabilities, logic bugs, or edge cases** that cause sensitive data to pass through the tool **unmodified and undetected**. Known risk areas include, but are not limited to:
>
> - Emails or IPs that do not match the expected regex patterns
> - Key-value pairs with unusual quoting or formatting
> - Malformed input that causes a rule to silently skip anonymization
> - Configuration mistakes that cause the entire tool to exit without processing any data
> - **In-memory retention**: real values are held as map keys for the duration of the run to ensure consistent mapping. The tool clears these maps and requests a GC pass before exiting, but Go strings are immutable and their underlying bytes are not zeroed. For high-sensitivity environments, also disable core dumps (`ulimit -c 0`) and ensure swap is encrypted or disabled.
>
>
> **You are solely responsible for verifying the output.** Always inspect the sanitized result before sharing it to confirm that all sensitive data has been removed.
>
> This software is provided **"as is"**, without any warranty of any kind, express or implied. The author is **not responsible for any data exposure** resulting from the tool failing to anonymize data correctly, partially, or at all.
>
> **Use at your own risk.**

---

`anonymize` is a streaming CLI tool written in Go that anonymizes sensitive data from **stdin** and writes sanitized output to **stdout**.

It is designed to work with:

- Plain text logs
- JSON
- YAML
- Terraform / HCL
- Mixed structured + unstructured text

The tool preserves formatting as much as possible and guarantees **consistent replacements within a single run**.

---

## ✨ Features

- Public IPv4 anonymization (configurable special/keep ranges)
- Private & special-use IP ranges preserved
- CIDR preservation (`8.8.8.8/22 → 111.111.111.111/22`)
- Email anonymization with domain mapping
- Username/key-value redaction across formats
- AWS account ID anonymization
- Bearer token anonymization
- Long hex token anonymization
- Config-driven rule engine (TOML)
- Fully streaming (constant memory)
- Extensible transformer architecture

---

## 📦 Installation

```bash
git clone <your_repo_url>
cd anonymize
go mod tidy
go build -o anonymize ./cmd/anonymize
```

---

## 🚀 Configuration & Usage

`anonymize` reads its configuration from:

- Default: `~/.anonymize.toml`
- Override: `--config /path/to/config.toml`

### Basic usage

```bash
cat file.txt | ./anonymize
```

With explicit config:

```bash
cat file.txt | ./anonymize --config ~/.anonymize.toml
```

Enable rule stats:

```bash
cat file.txt | ./anonymize --stats
```

### Try it with the included sample

The repository ships a ready-made test file that covers plain text, JSON, YAML, Terraform/HCL, tokens, IPs, and emails:

```bash
cat testdata/sample-input.txt | ./anonymize --stats
```

Inspect the output carefully to verify the anonymization is working as expected for your config before using it on real data.

---

### ⚙️ Default Config Location

```txt
~/.anonymize.toml
```

If `--config` is provided, it overrides the default path.

---

## 🧠 Anonymization Strategy

### Public IPv4 Mapping

Only **globally routable IPv4** addresses are anonymized.

All special-use / private ranges defined in `ip.keep_cidrs` are preserved.

Mapping sequence (per run):

| Original Public IP | Replaced With   |
| ------------------ | --------------- |
| 1st                | 111.111.111.111 |
| 2nd                | 122.122.122.122 |
| 3rd                | 133.133.133.133 |

Mapping formula:

```txt
octet = public_base + (n-1) * public_step
```

Example:

```txt
8.8.8.8       → 111.111.111.111
1.1.1.1       → 122.122.122.122
8.8.8.8/22    → 111.111.111.111/22
```

CIDR suffix is preserved.

Mapping key is the base IP only, meaning:

```txt
8.8.8.8
8.8.8.8/32
```

Both share the same base anonymized IP.

---

### Email Mapping

- First unique email → `user@example1.com`
- Second unique email → `user2@example1.com`
- New domain → `example2.com`

Repetitions map consistently within the same run.

Example:

```txt
alice@corp.internal → user@example1.com
bob@corp.internal   → user2@example1.com
charlie@other.com   → user3@example2.com
```

---

### Username / Key Redaction

Values for configured keys are replaced with:

```txt
[redacted]
```

Supported formats:

```txt
user=bob
user: bob
"user": "bob"
user = "bob"
principalId=ABC-123
```

---

### Token & ID Mapping

Tokens are replaced with incremental labels per rule:

```txt
token-1
token-2
aws-account-1
hex-1
```

Repeated values map consistently within the same run.

---

## 🛠 Configuration

The repository ships a fully commented example config that covers all available options:

```bash
cp anonymize-example.toml ~/.anonymize.toml
```

Open [`anonymize-example.toml`](anonymize-example.toml) to see every setting with inline documentation.

---

## 🧱 Architecture

The engine uses a transformer pipeline:

```txt
stdin → transformer1 → transformer2 → ... → stdout
```

Each rule type implements:

```txt
Apply(string) (string, error)
```

State is shared per run to guarantee consistent mappings.

Adding new functionality only requires:

1. Implementing a new Transformer
2. Registering it in the rule registry
3. Adding rule config in TOML

No core engine changes required.

---

## 📈 Performance

- Streaming (line-by-line)
- Bounded memory usage
- 10MB default max line size
- Suitable for large log files

---

## 🗺 Roadmap

- IPv6 anonymization
- JSON-aware structural redaction
- Structured log mode
- Unit test coverage
- GitHub Actions CI
- Release builds (darwin/arm64, linux/amd64)
- Homebrew support
- Benchmark suite

---

## 🐛 Reporting Issues & Contributing

Found a bug, an anonymization gap, or have a suggested fix? Contributions are welcome.

- **Open an issue** — use the [bug report](https://github.com/icadariu/anonymize/issues/new?template=bug_report.md) template if sensitive data passed through unmodified, or the [feature request](https://github.com/icadariu/anonymize/issues/new?template=feature_request.md) template for new ideas.
- **Open a pull request** — if you have a fix or improvement ready, submit a PR against `main`. Please fill in the PR template, include a sanitized input/output example, and confirm the change does not introduce a new anonymization gap.

> When reporting issues, **never include real sensitive data** in issue descriptions, comments, or PR diffs. Use synthetic or clearly fake examples instead.

---

## 📄 License

MIT
