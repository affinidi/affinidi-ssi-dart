# SD-JWT Dart SDK

[![Dart SDK Version](https://img.shields.io/badge/dart-%3E%3D3.6.0-blue.svg)](https://dart.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Dart SDK for working with Selective Disclosure JSON Web Tokens (SD-JWT) following the SD-JWT specification.

## Quick Start

```dart
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

void main() async {
  // 1. Create SD-JWT with selective disclosures
  final handler = SdJwtHandlerV1();

  final claims = {
    'given_name': 'Alice',
    'family_name': 'Smith',
    'email': 'alice@example.com',
  };

  // Mark which claims should be selectively disclosable
  final disclosureFrame = {
    '_sd': ['given_name', 'email']
  };

  // Create the SD-JWT
  final sdJwt = handler.sign(
    claims: claims,
    disclosureFrame: disclosureFrame,
    signer: SDKeySigner(issuerPrivateKey),
  );

  print("SD-JWT: ${sdJwt.serialized}");

  // 2. Verify the SD-JWT
  final verified = handler.decodeAndVerify(
    sdJwtToken: sdJwt.serialized,
    verifier: SDKeyVerifier(issuerPublicKey),
  );

  print("Verified claims: ${verified.claims}");
  // Output: {given_name: Alice, family_name: Smith, email: alice@example.com}
}
```

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Usage](#usage)
  - [Creating and Signing an SD-JWT](#creating-and-signing-an-sd-jwt)
  - [Presenting an SD-JWT](#presenting-an-sd-jwt)
  - [Verifying an SD-JWT](#verifying-an-sd-jwt)
  - [Working with Key Binding JWT (KB-JWT)](#working-with-key-binding-jwt-kb-jwt)
- [API Reference](#api-reference)
  - [SdJwtHandler](#sdjwthandler)
  - [SdJwt](#sdjwt)
  - [Keys and Signing](#keys-and-signing)
  - [Verification](#verification)
- [Examples](#examples)
- [Supported Algorithms](#supported-algorithms)
- [License](#license)

## Overview

The SD-JWT Dart SDK implements the [Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) and [SD-JWT-based Verifiable Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) specifications. It enables:

- **Issuers** to create JWTs with selectively disclosable claims
- **Holders** to present only specific claims to verifiers
- **Verifiers** to validate the authenticity of the presented claims
- **Key binding** to prevent unauthorized presentations

## Installation

Add the package to your `pubspec.yaml`:

```yaml
dependencies:
  sdjwt_sdk: ^1.0.0
```

Then run:

```bash
dart pub get
```

## Core Concepts

SD-JWT introduces several key concepts:

- **Selective Disclosure**: Claims can be selectively disclosed based on need
- **Cryptographic Binding**: Claims are cryptographically bound to the JWT
- **Key Binding**: Ensures only the intended holder can present the SD-JWT
- **Disclosures**: Individual pieces of information that can be selectively shared

## Usage

### Creating and Signing an SD-JWT

```dart
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

void createSdJwt() {
  // Create the claims to be included in the SD-JWT
  final claims = {
    'given_name': 'Alice',
    'family_name': 'Smith',
    'email': 'alice.smith@example.com',
    'birthdate': '1990-01-01',
    'address': {
      'street_address': '123 Main St',
      'locality': 'Anytown',
      'country': 'US'
    },
  };

  // Define which claims should be selectively disclosable
  final disclosureFrame = {
    '_sd': ['given_name', 'email', 'birthdate']
  };

  // Create issuer's private key for signing
  final issuerPrivateKey = SdPrivateKey(
    privateKeyPem, // Your private key in PEM format
    SdJwtAlgorithm.es256, // Choose appropriate algorithm
  );

  // Create the SD-JWT handler and signer
  final handler = SdJwtHandlerV1();
  final signer = SDKeySigner(issuerPrivateKey);

  // Sign the SD-JWT
  final sdJwt = handler.sign(
    claims: claims,
    disclosureFrame: disclosureFrame,
    signer: signer,
    // Optional: specify a different hasher
    // hasher: Base64EncodedOutputHasher.base64Sha512,
    // Optional: add holder key for key binding
    // holderPublicKey: holderPublicKey,
  );

  // Get the serialized SD-JWT
  final serialized = sdJwt.serialized;
  print("SD-JWT: $serialized");

  // Example output (truncated):
  // eyJhbGciOiJFUzI1NiIsInR5cCI6InNkK2p3dCJ9.eyJmYW1pbH...~eyJhbGciOiJFUzI1NiJ9.e30~
}
```

### Presenting an SD-JWT

```dart
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

void presentSdJwt(String serializedSdJwt) {
  // Parse the original SD-JWT without verification
  final handler = SdJwtHandlerV1();
  final sdJwt = handler.unverifiedDecode(sdJwtToken: serializedSdJwt);

  // Select which disclosures to keep (e.g., only share name and email, not birthdate)
  final disclosuresToKeep = sdJwt.disclosures.where(
    (d) => d.claimName == 'given_name' || d.claimName == 'email'
  ).toSet();

  // Create a presentation with only selected disclosures
  final presentation = handler.present(
    sdJwt: sdJwt,
    disclosuresToKeep: disclosuresToKeep,
  );

  // Get the serialized presentation to share with the verifier
  final presentationString = presentation.serialized;
  print("Presentation SD-JWT: $presentationString");

  // Example output (truncated):
  // eyJhbGciOiJFUzI1NiIsInR5cCI6InNkK2p3dCJ9.eyJmYW1pbH...~eyJhbGciOiJFUzI1NiJ9.e30~
}
```

### Verifying an SD-JWT

````dart
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

void verifySdJwt(String serializedSdJwt) {
  // Create verifier with issuer's public key
  final publicKey = SdPublicKey(
    publicKeyPem, // Issuer's public key in PEM format
    SdJwtAlgorithm.es256, // Same algorithm used for signing
  );
  final verifier = SDKeyVerifier(publicKey);

  // Create SD-JWT handler
  final handler = SdJwtHandlerV1();

  try {
    // Decode and verify the SD-JWT in one step
    final verificationResult = handler.decodeAndVerify(
      sdJwtToken: serializedSdJwt,
      verifier: verifier,
      // Optional: verify key binding if present
      verifyKeyBinding: true,
    );

    // Access verified claims
    print('Verification successful!');
    print('Claims: ${verificationResult.claims}');

    // Example output:
    // Verification successful!
    // Claims: {given_name: Alice, family_name: Smith, email: alice.smith@example.com}
  } catch (e) {
    print('Verification failed: $e');
  }
}

### Decoding and Verifying an SD-JWT from a String

When working with SD-JWTs created by someone else, you'll often receive them as strings. The SDK provides two methods to parse them:

```dart
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

void workWithExternalSdJwt(String receivedSdJwtString) {
  final handler = SdJwtHandlerV1();

  // Option 1: Decode without verification
  // Use this when you need to examine the contents without verifying the signature
  // For example, when you want to see what disclosures are available
  final decodedOnly = handler.unverifiedDecode(
    sdJwtToken: receivedSdJwtString,
    // Optional: provide a custom hasher if the SD-JWT uses a non-standard hashing algorithm
    // customHasher: myCustomHasher,
  );

  print('Decoded claims (unverified): ${decodedOnly.claims}');
  print('Available disclosures: ${decodedOnly.disclosures.length}');

  // Option 2: Decode and verify in one step
  // This verifies the signature against the issuer's public key
  try {
    final issuerPublicKey = SdPublicKey(
      publicKeyPem, // Issuer's public key in PEM format
      SdJwtAlgorithm.es256, // The algorithm used for signing
    );

    final verifier = SDKeyVerifier(issuerPublicKey);

    final verifiedResult = handler.decodeAndVerify(
      sdJwtToken: receivedSdJwtString,
      verifier: verifier,
      // Optional: verify the key binding JWT if present
      verifyKeyBinding: true,
    );

    // If we got here, verification succeeded
    print('Verified claims: ${verifiedResult.claims}');

    // Check the verification status
    if (verifiedResult.isVerified == true) {
      print('SD-JWT is fully verified');
    }
  } catch (e) {
    print('Verification failed: $e');
  }
}
````

### Working with Key Binding JWT (KB-JWT)

Key Binding JWT (KB-JWT) ensures that only the intended holder can present the SD-JWT:

```dart
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

void presentWithKeyBinding(String serializedSdJwt) {
  // Parse the SD-JWT without verification
  final handler = SdJwtHandlerV1();
  final sdJwt = handler.unverifiedDecode(sdJwtToken: serializedSdJwt);

  // Configure holder's key pair
  final holderPrivateKey = SdPrivateKey(
    holderPrivateKeyPem,
    SdJwtAlgorithm.es256,
  );
  final holderPublicKey = SdPublicKey(
    holderPublicKeyPem,
    SdJwtAlgorithm.es256,
  );

  // Create holder signer for key binding
  final holderSigner = SDKeySigner(holderPrivateKey);

  // Select which disclosures to keep
  final disclosuresToKeep = sdJwt.disclosures.where(
    (d) => d.claimName == 'given_name' || d.claimName == 'email'
  ).toSet();

  // Present with key binding
  final presentation = handler.present(
    sdJwt: sdJwt,
    disclosuresToKeep: disclosuresToKeep,
    presentWithKbJwtInput: PresentWithKbJwtInput(
      'https://verifier.example.com', // Audience (verifier)
      holderSigner,
      holderPublicKey,
    ),
  );

  // Get the serialized presentation with key binding
  final keyBoundPresentation = presentation.serialized;
  print("KB-JWT Presentation: $keyBoundPresentation");

  // Example output (truncated):
  // eyJhbGciOiJFUzI1NiIsInR5cCI6InNkK2p3dCJ9...~eyJhbGciOiJFUzI1NiJ9.e30~eyJhbGciOiJFUzI1NiJ9...
}
```

## API Reference

### SdJwtHandler

The main interface for SD-JWT operations:

- [`sign()`](https://pub.dev/documentation/sdjwt_sdk/latest/sdjwt_sdk/SdJwtHandler/sign.html) - Signs claims with selective disclosure capabilities
- [`present()`](https://pub.dev/documentation/sdjwt_sdk/latest/sdjwt_sdk/SdJwtHandler/present.html) - Creates a presentation from an existing SD-JWT
- [`verify()`](https://pub.dev/documentation/sdjwt_sdk/latest/sdjwt_sdk/SdJwtHandler/verify.html) - Verifies an SD-JWT and its disclosures
- [`decodeAndVerify()`](https://pub.dev/documentation/sdjwt_sdk/latest/sdjwt_sdk/SdJwtHandler/decodeAndVerify.html) - Decodes a serialized SD-JWT string and verifies it in one step. This is the recommended method for processing received SD-JWTs when you have the issuer's public key.
- [`unverifiedDecode()`](https://pub.dev/documentation/sdjwt_sdk/latest/sdjwt_sdk/SdJwtHandler/unverifiedDecode.html) - Decodes a serialized SD-JWT string without verifying the signature. Use this when you need to inspect an SD-JWT's contents before verification, such as when building UIs to display available disclosures.

### SdJwt

Represents a Selective Disclosure JWT:

- Properties:
  - `serialized` - The serialized string representation
  - `payload` - The decoded payload
  - `claims` - The complete set of claims after applying all disclosures
  - `disclosures` - The set of all disclosures
  - `jwsString` - The JWT part of the SD-JWT
  - `kbString` - The Key Binding JWT part (if present)

### Keys and Signing

- `SdPrivateKey` - Represents a private key for signing
- `SdPublicKey` - Represents a public key for verification
- `SDKeySigner` - Implements signing using SD-JWT keys
- `SDKeyVerifier` - Implements verification using SD-JWT keys
- `SdJwtAlgorithm` - Supported signing algorithms:
  - `es256` - ECDSA using P-256 curve and SHA-256
  - `es256k` - ECDSA using secp256k1 curve and SHA-256
  - `rs256` - RSASSA-PKCS1-v1_5 using SHA-256

### Verification

- `SdJwtVerifierOutput` - Contains the result of verification
  - `isVerified` - Whether the SD-JWT was successfully verified
  - `isKbJwtVerified` - Whether key binding JWT was verified

## Examples

### Creating a Nested Disclosure Structure

```dart
final claims = {
  'address': {
    'street': '123 Main St',
    'city': 'Anytown',
    'state': 'CA',
    'postal_code': '12345',
    'country': 'US'
  },
  'email': 'john.doe@example.com',
};

// Make email and specific address fields selectively disclosable
final disclosureFrame = {
  '_sd': ['email'],
  'address': {
    '_sd': ['street', 'postal_code']
  }
};

final sdJwt = handler.sign(
  claims: claims,
  disclosureFrame: disclosureFrame,
  signer: signer,
);

print("SD-JWT with nested disclosures: ${sdJwt.serialized}");
```

### Array Element Disclosures

```dart
final claims = {
  'phones': [
    {'type': 'home', 'number': '555-1234'},
    {'type': 'work', 'number': '555-5678'},
  ],
};

// Make the phone numbers selectively disclosable while keeping types visible
final disclosureFrame = {
  'phones': [
    {'_sd': ['number']},
    {'_sd': ['number']}
  ]
};

final sdJwt = handler.sign(
  claims: claims,
  disclosureFrame: disclosureFrame,
  signer: signer,
);

print("SD-JWT with array disclosures: ${sdJwt.serialized}");
```

## Supported Algorithms

The SDK supports the following signing algorithms:

- `ES256` - ECDSA using P-256 curve and SHA-256
- `ES256K` - ECDSA using secp256k1 curve and SHA-256
- `RS256` - RSASSA-PKCS1-v1_5 using SHA-256

For hash calculation in disclosures:

- `SHA-256` (default)
- `SHA-384`
- `SHA-512`

## License

This SDK is available under MIT license.
