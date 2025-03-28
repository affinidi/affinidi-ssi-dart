# Affinidi Dart SSI

Affinidi Dart SSI package provides libraries and tools for implementing Self-Sovereign Identity (SSI), a fundamental concept of managing digital identities in a decentralised manner. The Affinidi Dart SSI also offers additional libraries to enable selective disclosure using SD-JWT specification for enhanced security and privacy in the data-sharing process.

It supports various [Decentralised Identifier (DID)](https://www.w3.org/TR/did-1.0/) methods to represent an entity's identity in the decentralised ecosystem and leverages different key management solutions and standards for generating and managing cryptographic keys associated with the digital wallet.

## Table of Contents

  - [Support DID Methods](#supported-did-methods)
  - [Support Key Management](#supported-key-management)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Support & feedback](#support--feedback)
  - [Reporting technical issues](#reporting-technical-issues)
  - [Contributing](#contributing)

## Supported DID Methods

Affinidi Dart SSI package supports the following DID methods to prove control of an entity's digital identity.

- did:key - a self-contained and portable Decentralised Identifier (DID).

- did:peer - a Decentralised Identifier (DID) method designed for a secured peer-to-peer communication.

- did:web - relies on Domain Name System (DNS) and HTTPS to prove control of an identity through domain name ownership.

Each DID method serves as a means of resolving the DID document for signing and verifying [Verifiable Credentials (VCs)](https://www.w3.org/TR/vc-data-model/).

## Supported Key Management

Affinidi Dart SSI package supports the following key management solutions for securely managing keys associated with the digital wallet.

- **BIP32** - a standard for creating Hierarchical Deterministic (HD) wallets and generate multiple keys from a single seed. It primarily supports the secp256k1 elliptic curve.

- **SLIP0010** - extends the BIP32 standard, enabling support for other types of elliptic curve cryptography.

## Requirements

- Dart SDK version ^3.6.0

## Installation

Add the package into your pubspec.yaml file.

```yaml
dependencies:
  affinidi_dart_ssi: ^<version_number>
```

Then run the command below to install the package.

```bash
dart pub get
```

## Usage

After successfully installing the package, import it into your Dart code.

```dart

```

## Published on

The Affinidi Dart SSI and Selective Disclosure JWT (SD-JWT) packages are published on pub.dev repository.

- <dart_ssi_pub_dev_link>

- <sd-jwt_pub_dev_link>

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi TDK's codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-ssi-dart/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-ssi-dart/issues/new).
   Be sure to include a **title and clear description**, as much relevant information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](CONTRIBUTING.md) guidelines.


