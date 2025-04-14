import 'dart:typed_data';

import 'package:sdjwt/sdjwt.dart' show Verifier;
import 'package:ssi/ssi.dart' hide Verifier;

/// A DID-based verifier for SD-JWT credentials.
///
/// This class adapts the [DidVerifier] for use with the SD-JWT library's
/// verification interface, allowing SD-JWT credentials to be verified
/// using DID-based keys.
class SdJwtDidVerifier implements Verifier {
  /// The underlying DID verifier that performs the actual verification.
  final DidVerifier _delegate;

  /// Private constructor that creates a verifier with the given delegate.
  ///
  /// [_delegate] - The DID verifier to use for verification.
  SdJwtDidVerifier._(this._delegate);

  /// Creates a new SD-JWT DID verifier for the specified issuer and key.
  ///
  /// [algorithm] - The signature scheme used to sign the credential.
  /// [kid] - The key identifier within the DID Document.
  /// [issuerDid] - The DID of the issuer who signed the credential.
  /// [resolverAddress] - Optional DID resolver address for resolving DIDs.
  ///
  /// Returns a configured verifier ready to verify SD-JWT signatures.
  static Future<SdJwtDidVerifier> create({
    required SignatureScheme algorithm,
    required String kid,
    required String issuerDid,
    String? resolverAddress,
  }) async {
    final verifier = await DidVerifier.create(
      algorithm: algorithm,
      kid: kid,
      issuerDid: issuerDid,
      resolverAddress: resolverAddress,
    );

    return SdJwtDidVerifier._(verifier);
  }

  /// Checks if the provided algorithm is supported by this verifier.
  ///
  /// [algorithm] - The algorithm name to check.
  ///
  /// Returns true if the algorithm is supported, false otherwise.
  @override
  bool isAllowedAlgorithm(String algorithm) {
    return _delegate.isAllowedAlgorithm(algorithm);
  }

  /// Verifies a signature against the provided data.
  ///
  /// [data] - The signed data to verify.
  /// [signature] - The signature to verify against the data.
  ///
  /// Returns true if the signature is valid for the data, false otherwise.
  @override
  bool verify(Uint8List data, Uint8List signature) {
    return _delegate.verify(data, signature);
  }
}
