---
name: Bug report
about: Report a case where sensitive data was NOT anonymized, or the tool behaved unexpectedly
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear and concise description of what the bug is.

## Type of issue

- [ ] Sensitive data passed through **unmodified** (anonymization failure)
- [ ] Tool exited with an error and produced **no output**
- [ ] Incorrect / unexpected replacement
- [ ] Performance issue
- [ ] Other

## Input that triggered the issue

Provide a **sanitized or synthetic** sample of the input line(s) that caused the problem.
**Do NOT paste real sensitive data here.**

```
<paste sanitized input here>
```

## Expected behavior

What should the tool have done?

## Actual behavior

What did the tool actually do? Include any error messages printed to stderr.

```
<paste actual output or error here>
```

## Config used

Paste the relevant section(s) of your `~/.anonymize.toml`.
Remove any real hostnames, domain names, or other sensitive values before posting.

```toml
<paste config here>
```

## Environment

- OS: (e.g. Ubuntu 22.04, macOS 14)
- Go version: (run `go version`)
- Tool version / commit: (run `git rev-parse --short HEAD`)

## Additional context

Any other context, regex patterns, or notes that might help diagnose the issue.
