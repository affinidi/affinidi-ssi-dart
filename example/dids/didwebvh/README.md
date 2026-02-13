# didwebvh playground cli

Usage:

```bash
dart run bin/webvh_cli.dart resolve <did.jsonl|did:webvh:...> [--verify] [--details]

```

## Verify DID Log

Verify local did josn log file with correct content:

```bash
dart run bin/webvh_cli.dart resolve did.jsonl
```

Verify local did json log file with tampered content:

```bash
dart run bin/webvh_cli.dart resolve did-tampered.jsonl # or did.jsonl with manual tampering
```
