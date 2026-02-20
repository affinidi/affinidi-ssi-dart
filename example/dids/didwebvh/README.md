# didwebvh playground cli

## Usage

```bash
./didwebvh.sh resolve <did.jsonl|did:webvh:...> [--no-verify]
```

## Example Cases

### Bob - Basic DID with 2 versions, simple update with ttl

```bash
./didwebvh.sh resolve did:webvh:QmZy6fnQzZKfH2CEnDWzkt1BtgRhfom8juF2P5mTGjKw1Z:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob
```

### Alice - Basic DID with single version

```bash
./didwebvh.sh resolve did:webvh:QmVaiNkBJVpNZ1cuWBBWAmzayukSMdMEtSJCwntHA96eov:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice
```

### DID with witness configuration (3 versions)

```bash
./didwebvh.sh resolve did:webvh:QmXi6hYqAUBKevKkUAbETFa6LKjvCSnuxdS1icQtiR4SAi:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness
```

### DID with pre-rotation using nextKeyHashes (3 versions)

```bash
./didwebvh.sh resolve did:webvh:QmQLNyCy7vjze7KVwAYnAG2PiDuMwwSatp49H2E8GHPAaf:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-pre-rotated
```

### DID with rotated authentication key (2 versions)

DID with rotated authentication key (2 versions).

```bash
./didwebvh.sh resolve did:webvh:QmeHX9xa1QWjG2GWiTZTVMzeMwrBfSneUZ7P5GiZUiuk5C:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-rotated-auth
```

### SCID does not match hash of first entry - should fail verification

```bash
./didwebvh.sh resolve did:webvh:QmQtjyJQVUCWLqUZkCmuRnWCq7HfimDP2ohgvgMzuVG6qX:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-invalid-scid
```

### Entry hash mismatch (tampered versionId) - should fail verification

```bash
./didwebvh.sh resolve did:webvh:QmUaJLRY8S3tNaGuCNz1DwWo7nthfRmuFQYB18LMGgu4Lq:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-tampered
```

## Resolve All Examples

```bash
./resolve-all.sh
```

## Local File Resolution

Resolve local did.jsonl file:

```bash
./didwebvh.sh resolve bob/did.jsonl
```

Resolve without verification:

```bash
./didwebvh.sh resolve bob-tampered/did.jsonl --no-verify
```
