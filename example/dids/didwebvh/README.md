# didwebvh playground cli

## Usage

```bash
./didwebvh.sh resolve <did.jsonl|did:webvh:...> [--no-verify]
```

## Example Cases

### Bob - Basic DID with 2 versions, simple update with ttl

```bash
./didwebvh.sh resolve did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob
```

### Alice - Basic DID with single version

```bash
./didwebvh.sh resolve did:webvh:QmWufN4thhDrVPsnUXF7JjxvaexfA5N1C69R2rmtyTmHDP:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice
```

### DID with witness configuration (3 versions)

```bash
./didwebvh.sh resolve did:webvh:Qme2PYT44CZFzmT4ReHqGXAX4SVijyLCDJVELa6iBqXV1M:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness
```

### DID with pre-rotation using nextKeyHashes (3 versions)

```bash
./didwebvh.sh resolve did:webvh:QmWPo9k2HL88tqFLHnnSszJWiwasYC7ZNEXikPr7hnNZjU:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-pre-rotated
```

### DID with rotated authentication key (2 versions)

DID with rotated authentication key (2 versions).

```bash
./didwebvh.sh resolve did:webvh:QmTCsSL1Tkv7MFBbL9KvCEEmy9LdePBvBPfoNY4NudvxqL:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-rotated-auth
```

### SCID does not match hash of first entry - should fail verification

```bash
./didwebvh.sh resolve did:webvh:QmeKJku2EXguV8GGfoEnSzLev5y19UV7GantscVAissymp:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-invalid-scid
```

### Entry hash mismatch (tampered versionId) - should fail verification

```bash
./didwebvh.sh resolve did:webvh:QmSgM3nsNxmFKyhiaPvk2nMAvjK4hqQwTHnJCKbHohtSq8:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-tampered
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
