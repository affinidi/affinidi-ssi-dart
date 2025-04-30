# Dart SSI Examples

Check the code snippets to learn how to integrate this package with your project.

## Wallet and DID

### 1. Create a Wallet

Create a Hierarchical Deterministic wallet with BIP32 support - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/wallet/bip32_wallet.dart).

Create a Non-Hierarchical Deterministic wallet with a P256 key type - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/wallet/persistent_wallet.dart).


### 2. Resolve DID Document

Resolve the DID Document from one of the [supported methods](https://github.com/affinidi/affinidi-ssi-dart/blob/main/README.md#supported-did-methods) to extract information such as public key information - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/universal_did_resolver.dart).

### 3. Create a DID Signer

Create a DID signer using the BIP32 wallet - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/did/did_signer.dart).

<hr />


## Verifiable Credential (VC) Data Model V1

### 1. Create and Sign Verifiable Credential (VC)

Create a Verifiable Credential with a mutable data using Data Model V1 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc/ld_v1/issuance.dart).


### 2. Verify VC Expiry and Integrity

Verify the expiration of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc/ld_v1/verification/expiry_verification.dart).

Verify the integrity of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc/ld_v1/verification/integrity_verification.dart).

### 3. Create Data Model

Create a data model using V1 - [view example](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/code_snippets/credentials/vc/ld_v1/data_model_creation.dart).

### 4. Parse VC String

Parse a Data Model V1 VC string - [view example](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/code_snippets/credentials/vc/ld_v1/parsing.dart).


## Verifiable Credential (VC) Data Model V2

### 1. Create and Sign Verifiable Credential (VC)

Create a Verifiable Credential with a mutable data using Data Model V2 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc/ld_v2/issuance.dart).

### 2. Create and Sign SD-JWT

Create a SD-JWT with a mutable data - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vc/sdjwt/issuance.dart).

### 3. Create Data Model

Create a data model using V1 - [view example](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/code_snippets/credentials/vc/ld_v2/data_model_creation.dart).

### 4. Parse VC String

Parse a Data Model V2 VC string - [view example](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/code_snippets/credentials/vc/ld_v2/parsing.dart).

<hr />

## Verifiable Presentation (VP) Data Model V1

### 1. Create and Sign Verifiable Presentation (VP)

Create a Verifiable Presentation with a mutable presentation using VP Data Model V1 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v1/issuance.dart).

### 2. Verify VP Expiry and Integrity

Verify the expiration of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v1/verification/expiry_verification.dart).

Verify the integrity of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v1/verification/integrity_verification.dart).


### 3. Verify VP with Custom Challenge

Verify the VP with specific domain and challenge using Data Model V1 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v1/verification/domain_challenge_verification.dart).

### 4. Parse VP String

Parse a Data Model V1 VP string - [view example](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/code_snippets/credentials/vp/ld_v1/parsing.dart).


## Verifiable Presentation (VP) Data Model V2

### 1. Create and Sign Verifiable Presentation (VP)

Create a Verifiable Presentation with a mutable presentation using VP Data Model V2 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v2/issuance.dart).

### 2. Verify VP Expiry and Integrity

Verify the expiration of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v2/verification/expiry_verification.dart).

Verify the integrity of the Verifiable Credential - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v2/verification/integrity_verification.dart).


### 3. Verify VP with Custom Challenge

Verify the VP with specific domain and challenge using Data Model V2 - [view example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials/vp/ld_v2/verification/domain_challenge_verification.dart).

### 4. Parse VP String

Parse a Data Model V2 VP string - [view example](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/code_snippets/credentials/vp/ld_v2/parsing.dart).
