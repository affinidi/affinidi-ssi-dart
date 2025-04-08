import 'dart:typed_data';

/// Interface for verifying signature
abstract interface class Verifier {
  /// Checks if the specified algorithm is supported by this verifier.
  ///
  /// Returns true if the algorithm is supported, false otherwise.
  bool isAllowedAlgorithm(String algorithm);

  /// Verifies that the signature matches the data.
  ///
  /// Returns true if the signature is valid, false otherwise.
  bool verify(Uint8List data, Uint8List signature);
}
