#!/bin/bash
set +e # explicitly allow commands to fail without exiting the script

echo "=== bob: basic DID with 2 versions, simple update with ttl ==="
./didwebvh.sh resolve did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob

echo "=== alice: basic DID with single version ==="
./didwebvh.sh resolve did:webvh:QmWufN4thhDrVPsnUXF7JjxvaexfA5N1C69R2rmtyTmHDP:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice

echo "=== alice-with-witness: DID with witness configuration (3 versions) ==="
./didwebvh.sh resolve did:webvh:Qme2PYT44CZFzmT4ReHqGXAX4SVijyLCDJVELa6iBqXV1M:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness

echo "=== bob-pre-rotated: DID with pre-rotation using nextKeyHashes (3 versions) ==="
./didwebvh.sh resolve did:webvh:QmWPo9k2HL88tqFLHnnSszJWiwasYC7ZNEXikPr7hnNZjU:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-pre-rotated

echo "=== bob-rotated-auth: DID with rotated authentication key (2 versions) ==="
./didwebvh.sh resolve did:webvh:QmTCsSL1Tkv7MFBbL9KvCEEmy9LdePBvBPfoNY4NudvxqL:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-rotated-auth

echo "=== bob-invalid-scid: INVALID - SCID does not match hash of first entry ==="
./didwebvh.sh resolve did:webvh:QmeKJku2EXguV8GGfoEnSzLev5y19UV7GantscVAissymp:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-invalid-scid

echo "=== bob-tampered: INVALID - entry hash mismatch (tampered versionId) ==="
./didwebvh.sh resolve did:webvh:QmSgM3nsNxmFKyhiaPvk2nMAvjK4hqQwTHnJCKbHohtSq8:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-tampered


echo "=== Incorrect versionTime: INVALID - versionTime is the same in 2 records ==="
./didwebvh.sh did:webvh:QmVJ5nUYb9iugnUz4yDfbe8UFbhmnsvS2EAzSpSfPScRAn:opsecid.github.io
