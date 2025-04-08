# Affinidi Dart SSI

Affinidi Dart SSI package provides libraries and tools for implementing Self-Sovereign Identity (SSI), a fundamental concept of managing digital identities in a decentralised manner.

It supports various [Decentralised Identifier (DID)](https://www.w3.org/TR/did-1.0/) methods to represent an entity's identity in the decentralised ecosystem. It leverages different key management solutions and standards for generating and managing cryptographic keys associated with the digital wallet.

> **IMPORTANT:** 
> This project does not collect or process personal data by default. However, when used as part of a broader system or application that handles personally identifiable information (PII), users are responsible for ensuring that any such use complies with applicable privacy laws and data protection obligations.

## Table of Contents

  - [Supported DID Methods](#supported-did-methods)
  - [Supported Key Management](#supported-key-management)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Support & feedback](#support--feedback)
  - [Contributing](#contributing)

## Supported DID Methods

Affinidi Dart SSI package supports the following DID methods to prove control of an entity's digital identity.

- did:key - a self-contained and portable Decentralised Identifier (DID).

- did:peer - a Decentralised Identifier (DID) method designed for secured peer-to-peer communication.

- did:web - relies on Domain Name System (DNS) and HTTPS to prove control of an identity through domain name ownership.

Each DID method provides different ways to store and manage DID documents containing information associated with the DID, such as service endpoints and public keys for encrypting and verifying data.

## Supported Key Management

Affinidi Dart SSI package supports the following key management solutions for securely managing keys associated with the digital wallet.

- **BIP32** - a standard for creating Hierarchical Deterministic (HD) wallets and generating multiple keys from a single seed. It primarily supports the secp256k1 elliptic curve.

- **BIP32 ED25519** - adapts the BIP32 standard to work with the ED25519 elliptic curve cryptography.

## Requirements

- Dart SDK version ^3.6.0

## Installation

Add the package into your pubspec.yaml file.

```yaml
dependencies:
  affinidi_dart_ssi: ^<version_number>
```

Then, run the command below to install the package.

```bash
dart pub get
```

Visit the pub.dev install page of the Affinidi SSI Dart package for more information.

## Usage

After successfully installing the package, import it into your Dart code.

For a complete example of how to use the package, see the [example/main.dart](https://github.com/affinidi/affinidi-ssi-dart/blob/main/example/main.dart) file.

For more sample usage, go to the [example folder](example).

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi Dart SSI's codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-ssi-dart/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-ssi-dart/issues/new).
   Be sure to include a **title and clear description**, as much relevant information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](CONTRIBUTING.md) guidelines.


