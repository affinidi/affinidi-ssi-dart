# Affinidi SSI

SSI package provides libraries and tools for implementing Self-Sovereign Identity (SSI), a fundamental concept of managing digital identities in a decentralised manner.

It supports various [Decentralised Identifier (DID)](https://www.w3.org/TR/did-1.0/) methods to represent an entity's identity in the decentralised ecosystem. It leverages different key management solutions and standards for generating and managing cryptographic keys associated with the digital wallet.

> **IMPORTANT:** 
> This project does not collect or process any personal data. However, when used as part of a broader system or application that handles personally identifiable information (PII), users are responsible for ensuring that any such use complies with applicable privacy laws and data protection obligations.

## Table of Contents

  - [Core Concepts](#core-concepts)
  - [Supported DID Methods](#supported-did-methods)
  - [Supported Key Management](#supported-key-management)
  - [Credential Data Models](#credential-data-models)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Support & feedback](#support--feedback)
  - [Contributing](#contributing)


## Core Concepts

SSI introduces several key concepts:

- **Decentralised Identifier (DID):** A globally unique identifier that enables secure interactions. The DID is the cornerstone of Self-Sovereign Identity (SSI), a concept that aims to put individuals or entities in control of their digital identities. DID has different methods to prove control of digital identity.

- **Verifiable Credential (VC):** A digital representation of a claim created by the issuer about the subject (e.g., Individual). VC is cryptographically signed and verifiable.

- **Verifiable Presentation (VP):** A collection of one or more Verifiable Credentials (VCs) that an individual shares with the verifier to prove specific claims. VP is cryptographically signed and verifiable.

- **Data Model:** A standard data structure defined by W3C  for consistency and interoperability.

- **Wallet:** A digital wallet to manage cryptographic keys supporting different algorithms for signing and verifying VC and VP.

## Supported DID Methods

The package supports the following DID methods to prove control of an entity's digital identity:

- **did:key** - a self-contained and portable Decentralised Identifier (DID).

- **did:peer** - a Decentralised Identifier (DID) method designed for secured peer-to-peer communication.

- **did:web** - relies on Domain Name System (DNS) and HTTPS to prove control of an identity through domain name ownership.

Each DID method provides different ways to store and manage DID documents containing information associated with the DID, such as service endpoints and public keys for encrypting and verifying data.

Refer to [this example](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/universal_did_resolver.dart) to resolve a DID Document using one of the supported methods.

## Supported Key Management

This package supports the following key management solutions for securely managing keys associated with the digital wallet:

- **BIP32** - a standard for creating Hierarchical Deterministic (HD) wallets and generating multiple keys from a single seed. It primarily supports the secp256k1 elliptic curve.

- **BIP32 ED25519** - adapts the BIP32 standard to work with the ED25519 elliptic curve cryptography.

- **Persistent Wallet** - A Non-Hierarchical Deterministic wallet that supports different key types (e.g., P256 and ED25519).

Refer to [these examples](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/wallet) to learn how to create different wallets.

## Credential Data Models

The package supports the following Credential Models to create Verifiable Credentials (VCs) and Verifiable Presentations (VPs).

- **LD Model V1** - follows the W3C Data Model V1 for [Verifiable Credential (VC)](https://www.w3.org/TR/vc-data-model-1.0/) and [Verifiable Presentation (VP)](https://www.w3.org/TR/vc-data-model-1.0/#presentations-0).

- **LD Model V2** - follows the W3C Data Model V2 for [Verifiable Credential (VC)](https://www.w3.org/TR/vc-data-model-2.0/) and [Verifiable Presentation (VP)](https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations).

Each implementation of the data models enables you to create a Verifiable Credential and Verifiable Presentation that has:

- Mutable and Immutable fields.

- Mutable and Immutable data.

The Suite Data Model is the final form of the VC that encapsulates the signed VC, including additional attributes like the disclosures for SD-JWT VC and the JWT Header for JWT VC. The Suite Service provides the functions for parsing, serialising, and issuing a VC for a specific format.

Refer to [these examples](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example/code_snippets/credentials) to learn how to create and verify credentials using different models.

## Requirements

- Dart SDK version ^3.6.0

## Installation

Run:

```bash
dart pub add ssi
```

or manually, add the package into your `pubspec.yaml` file:

```yaml
dependencies:
  ssi: ^<version_number>
```

and then run the command below to install the package:

```bash
dart pub get
```

Visit the pub.dev install page of the Affinidi's SSI package for more information.

## Usage

After successfully installing the package, import it into your code.

```dart
import 'dart:typed_data';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final keyId = "m/44'/60'/0'/0'/0'";
  final wallet = Bip32Wallet.fromSeed(seed);

  print("Signing and verifying from root key");
  final data = Uint8List.fromList([1, 2, 3]);
  print('data to sign: ${hexEncode(data)}');
  final signature = await wallet.sign(data, keyId: keyId);
  print('signature: ${hexEncode(signature)}');
  final isRootSignatureValid =
      await wallet.verify(data, signature: signature, keyId: keyId);
  print('check if root signature is valid: $isRootSignatureValid');

  // generate DID document
  final key = await wallet.generateKey(keyId: keyId);
  final did = DidKey.getDid(key.publicKey);
  print('DID from public key: $did');
  final doc = DidKey.generateDocument(key.publicKey);
  print('DID document from public key: $doc');

}
```

For more sample usage, go to the [example folder](https://github.com/affinidi/affinidi-ssi-dart/tree/main/example).

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi SSI's codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-ssi-dart/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-ssi-dart/issues/new).
   Be sure to include a **title and clear description**, as much relevant information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-ssi-dart/blob/main/CONTRIBUTING.md) guidelines.


