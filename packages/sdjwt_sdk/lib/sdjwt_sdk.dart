/// SD-JWT SDK for Dart.
///
/// This library provides an implementation of the Selective Disclosure JWT (SD-JWT)
/// specification, allowing issuers to create JWTs with selectively disclosable claims,
/// holders to present only specific claims to verifiers, and verifiers to validate
/// the authenticity of the presented claims.
///
/// The library supports:
/// - Creating and signing SD-JWTs with selectively disclosable claims
/// - Key binding to prevent unauthorized presentations
/// - Verification of SD-JWTs and their disclosures
/// - Cryptographic operations using various algorithms (RS256, ES256, etc.)
///
/// Example usage:
/// ```dart
/// // Create an SD-JWT handler
/// final handler = SdJwtHandlerV1();
///
/// // Sign claims with selective disclosure
/// final sdJwt = await handler.sign(
///   claims: {"name": "Alice", "age": 25},
///   disclosureFrame: {"_sd": ["age"]},
///   issuerPrivateKey: privateKey,
/// );
///
/// // Verify an SD-JWT
/// final result = await handler.verify(
///   sdJwt: sdJwtString,
///   issuerKey: publicKey,
/// );
/// ```
library;

// Core API
export 'src/models/disclosure.dart';
export 'src/models/disclosure_path.dart';
export 'src/models/sdjwt.dart' show SdJwt, SdJwtStatus, disclosureSeparator;
export 'src/models/sdkey.dart';
export 'src/sd_jwt_handler_v1.dart';
export 'src/api.dart' show PresentWithKbJwtInput;
export 'src/base/hasher.dart';
export 'src/sign/signer.dart';
export 'src/verify/verifier.dart';
// Utilities
