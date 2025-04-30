# Dart SSI Examples

Check the code snippets to learn how to integrate this package with your project.

## Wallet & DID

### 1. Create a Wallet

Create a Hierarchical Deterministic wallet with BIP32 support - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/wallet/bip32_wallet.dart).

Create a Non-Hierarchical Deterministic wallet with a P256 key type - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/wallet/persistent_wallet.dart).


### 2. Resolve DID Document

Resolve the DID Document from one of the [supported methods](https://github.com/affinidi/affinidi-ssi-dart/blob/main/README.md#supported-did-methods) to extract information such as public key information - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/universal_did_resolver.dart).

### 3. Create a DID Signer

Create a DID signer using the BIP32 wallet - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/did_signer.dart).

## Verifiable Credential (VC)

### 1. Create and Sign Verifiable Credential (VC)

Create a Verifiable Credential with a mutable data - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc_issuance.dart).

### 2. Verify VC Expiry and Integrity

Verify the expiration of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc_expiry_verification.dart).

Verify the integrity of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc_integrity_verification.dart).

## Verifiable Presentation (VP)

### 1. Create and Sign Verifiable Presentation (VP)

Create a Verifiable Presentation with a mutable presentation using VP Data Model V1 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp_v1_issuance.dart).

Create a Verifiable Presentation with a mutable presentation using VP Data Model V2 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp_v2_issuance.dart).

> This example combines VCs created using data model V1 and V2, including SD-JWT V2.

### 2. Verify VP Expiry and Integrity

Verify the expiration of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp_expiry_verification.dart).

Verify the integrity of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp_integrity_verification.dart).


### 3. Verify VP with Custom Challenge

Verify the VP with specific domain and challenge - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp_domain_challenge_verification.dart).
