---
name: Bug report
about: Something exav does that it should not, or fails to do
title: ''
labels: bug
assignees: ''
---

## Do not attach a live sample

If a malicious file is involved, give its **SHA-256** and where it can be
obtained (MalwareBazaar, VirusTotal, the vendor). Do not attach the file, paste
its bytes, or link to a copy you are hosting.

If the file is *not* malicious — a benign archive exav mishandles, a document
that fails to parse — attaching it is fine and helps a great deal.

## What happened

## What you expected

## How to reproduce

```
exav ...
```

## Verdict and output

Paste the full output, including the verdict line. If the verdict was
`UNSCANNABLE`, `LIMITS-EXCEEDED` or `PASSWORD-PROTECTED`, include the reason —
those are not errors, and the reason is the part that identifies the cause.

## Environment

- exav version (`exav --version`):
- Installed how (cargo / release binary / container / npm):
- OS and architecture:
- Signature database and its date, if relevant:

## Anything else

Whether it reproduces consistently, whether it worked on another version, and
anything you already ruled out.
