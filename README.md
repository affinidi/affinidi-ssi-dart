# Affinidi SSI

SSI package provides libraries and tools for implementing Self-Sovereign Identity (SSI), a fundamental concept of managing digital identities in a decentralised manner.

It supports various [Decentralised Identifier (DID)](https://www.w3.org/TR/did-1.0/) methods to represent an entity's identity in the decentralised ecosystem. It leverages different key management solutions and standards for generating and managing cryptographic keys associated with the digital wallet.

> **IMPORTANT:** 
> This project does not collect or process personal data by default. However, when used as part of a broader system or application that handles personally identifiable information (PII), users are responsible for ensuring that any such use complies with applicable privacy laws and data protection obligations.

## Table of Contents

  - [Supported DID Methods](#supported-did-methods)
  - [Supported Key Management](#supported-key-management)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Universal DID resolver](#universal-did-resolver)
  - [Support & feedback](#support--feedback)
  - [Contributing](#contributing)
  - [Tests](#tests)

## Supported DID Methods

The package supports the following DID methods to prove control of an entity's digital identity:

- did:key - a self-contained and portable Decentralised Identifier (DID).

- did:peer - a Decentralised Identifier (DID) method designed for secured peer-to-peer communication.

- did:web - relies on Domain Name System (DNS) and HTTPS to prove control of an identity through domain name ownership.

Each DID method provides different ways to store and manage DID documents containing information associated with the DID, such as service endpoints and public keys for encrypting and verifying data.

## Supported Key Management

The following key management solutions are supported for securely managing keys associated with the digital wallet:

- **BIP32** - a standard for creating Hierarchical Deterministic (HD) wallets and generating multiple keys from a single seed. It primarily supports the secp256k1 elliptic curve.

- **BIP32 ED25519** - adapts the BIP32 standard to work with the ED25519 elliptic curve cryptography.

## Requirements

- Dart SDK version ^3.6.0

## Installation

Add the package into your pubspec.yaml file.

```yaml
dependencies:
  ssi: ^<version_number>
```

Then, run the command below to install the package.

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

  final wallet = Bip32Wallet.fromSeed(seed);

  // from wallet with root key
  print("Signing and verifying from root key");
  final rootKeyId = "0-0";
  final data = Uint8List.fromList([1, 2, 3]);
  print('data to sign: ${hexEncode(data)}');
  final signature = await wallet.sign(data, keyId: rootKeyId);
  print('signature: ${hexEncode(signature)}');
  final isRootSignatureValid =
      await wallet.verify(data, signature: signature, keyId: rootKeyId);
  print('check if root signature is valid: $isRootSignatureValid');

  // did
  final rootKeyPair = await wallet.getKeyPair(rootKeyId);
  final rootDidKey = await DidKey.create([rootKeyPair]);
  print('root did: $rootDidKey');
  final rootPublicKeyFromDid = await rootDidKey.publicKey;
  print('public key from root did: ${hexEncode(rootPublicKeyFromDid)}');

  // from derived key pair
  print("Signing and verifying from profile key");
  // NOTE: how to know what is the next available account index?
  final profileKeyId = "1234-0";
  final profileKeyPair = await wallet.createKeyPair(profileKeyId);
  final profileSignature = await profileKeyPair.sign(data);
  print('profile signature: ${hexEncode(profileSignature)}');
  final isProfileSignatureValid =
      await profileKeyPair.verify(data, signature: profileSignature);
  print(
      'check if profile signature is valid by public key: $isProfileSignatureValid');

  // did
  final profileDidKey = await DidKey.create([profileKeyPair]);
  print('profile did: $profileDidKey');
  final profilePublicKeyFromDid = await profileDidKey.publicKey;
  print('public key from profile did: ${hexEncode(profilePublicKeyFromDid)}');

  // second profile key
  print("Signing and verifying from second profile key");
  final profileKeyId2 = "1234-1";
  final profileKeyPair2 = await wallet.createKeyPair(profileKeyId2);
  final profileSignature2 = await profileKeyPair2.sign(data);
  print('profile signature 2: ${hexEncode(profileSignature2)}');
  final isProfileSignature2Valid =
      await profileKeyPair2.verify(data, signature: profileSignature2);
  print(
      'check if profile signature 2 is valid by public key: $isProfileSignature2Valid');
}
```

For more sample usage, go to the [example folder](example).

## Universal DID resolver

To resolve a DID Document for one of the [supported methods](#supported-did-methods), simply pass a DID to the resolve method, as shown in the example below:

```dart
import 'package:ssi/src/did/universal_did_resolver.dart';

void main() async {
  final didKeyDocument = await UniversalDIDResolver.resolve(
    'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2',
  );
  print('Resolved did:key document: $didKeyDocument');

  final didPeerDocument = await UniversalDIDResolver.resolve(
    'did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy',
  );
  print('Resolved did:peer document: $didPeerDocument');

  final didWebDocument = await UniversalDIDResolver.resolve(
    'did:web:demo.spruceid.com',
  );
  print('Resolved did:web document: $didWebDocument');
}
```

## Tests

There is an example of how wallet can be initialized with AWS KMS.
Make sure localstack with KMS is running in Docker, then run

```bash
dart test
```

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

Head over to our [CONTRIBUTING](CONTRIBUTING.md) guidelines.


