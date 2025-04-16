import 'dart:typed_data';

import '../key_pair/public_key.dart';
import '../types.dart';

/// An abstract interface for cryptographic key pairs used for signing and verifying data.
abstract interface class KeyPair {
  /// Returns a list of [SignatureScheme]s supported by this key pair.
  List<SignatureScheme> get supportedSignatureSchemes;

  /// Returns the public key as a [PublicKey].
  Future<PublicKey> get publicKey;

  /// Returns the private key as [Uint8List].
  Future<Uint8List> get privateKey;

  /// Signs the given [data] using the private key and optionally a [signatureScheme].
  ///
  /// [data] - The data to be signed.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature as a [Uint8List].
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  });

  /// Verifies a signature for the given [data] using the public key and optionally a [signatureScheme].
  ///
  /// [data] - The data that was signed.
  /// [signature] - The signature to verify.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with `true` if the signature is valid, `false` otherwise.
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  });

  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey});

  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey});
}
