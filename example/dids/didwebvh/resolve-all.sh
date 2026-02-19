#!/bin/bash
set +e # explicitly allow commands to fail without exiting the script

echo "=== bob: basic DID with 2 versions, simple update with ttl ==="
./didwebvh.sh resolve did:webvh:QmZy6fnQzZKfH2CEnDWzkt1BtgRhfom8juF2P5mTGjKw1Z:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob

echo "=== alice: basic DID with single version ==="
./didwebvh.sh resolve did:webvh:QmVaiNkBJVpNZ1cuWBBWAmzayukSMdMEtSJCwntHA96eov:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice

echo "=== alice-with-witness: DID with witness configuration (3 versions) ==="
./didwebvh.sh resolve did:webvh:QmXi6hYqAUBKevKkUAbETFa6LKjvCSnuxdS1icQtiR4SAi:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness

echo "=== bob-pre-rotated: DID with pre-rotation using nextKeyHashes (3 versions) ==="
./didwebvh.sh resolve did:webvh:QmQLNyCy7vjze7KVwAYnAG2PiDuMwwSatp49H2E8GHPAaf:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-pre-rotated

echo "=== bob-rotated-auth: DID with rotated authentication key (2 versions) ==="
./didwebvh.sh resolve did:webvh:QmeHX9xa1QWjG2GWiTZTVMzeMwrBfSneUZ7P5GiZUiuk5C:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-rotated-auth

echo "=== bob-invalid-scid: INVALID - SCID does not match hash of first entry ==="
./didwebvh.sh resolve did:webvh:QmQtjyJQVUCWLqUZkCmuRnWCq7HfimDP2ohgvgMzuVG6qX:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-invalid-scid

echo "=== bob-tampered: INVALID - entry hash mismatch (tampered versionId) ==="
./didwebvh.sh resolve did:webvh:QmUaJLRY8S3tNaGuCNz1DwWo7nthfRmuFQYB18LMGgu4Lq:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob-tampered
