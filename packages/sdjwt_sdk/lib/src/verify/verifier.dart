import 'dart:typed_data';

/// An abstract class representing a [Verifier] with well defined capabilities.
/// Any provided implementation should be able to [verify] the given signature bytes for the given data bytes
abstract interface class Verifier {
  /// Checks if the algorithm used by the JWS is allowed by the verifier.
  /// This is checked before starting the verification process.
  ///
  /// Parameters:
  /// - **[algorithm]**: The IANA algorithm name used by the JWS
  ///
  /// Returns whether the Verifier accepts / supports the algorithm or not.
  bool isAllowedAlgorithm(String algorithm);

  /// Verify the signature bytes, for the given data bytes. The exact algorithm or key
  /// material used for the verification is implementation specific.
  ///
  /// Parameters:
  /// - **[data]**: The data bytes
  /// - **[signature]**: The signature bytes
  ///
  /// Returns whether the signature is correct
  bool verify(Uint8List data, Uint8List signature);
}
