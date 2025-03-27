import 'dart:typed_data';

/// An abstract class representing a [Signer] with well defined capabilities.
/// Any provided implementation should be able to [sign] the given bytes and be able to
/// provide additional details about the signing algorithm name and verification id used.
abstract interface class Signer {
  /// Cryptographically sign the given bytes
  ///
  /// Parameters:
  /// - **[input]**: The bytes to be signed
  ///
  /// Returns the signature bytes.
  Uint8List sign(Uint8List input);

  /// Returns the IANA algorithm name to be included in the JWT header.
  String get algIanaName;

  /// (Optional) Returns the verification id to be included in the JWT `kid` header
  /// to help the verifiers deduce the corresponding verification method.
  String? get keyId;
}
