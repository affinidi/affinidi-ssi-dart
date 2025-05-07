import 'dart:typed_data';

import '../../ssi.dart';

/// An abstract interface for cryptographic key pairs used for signing and verifying data.
abstract interface class KeyPair {
  /// id of the key pair
  String get id;

  /// Returns a list of [SignatureScheme]s supported by this key pair.
  List<SignatureScheme> get supportedSignatureSchemes;

  /// Returns the public key as as a touple with the type and bytes.
  PublicKey get publicKey;

  /// Signs the provided data using P-256 with SHA-256 hashing (ecdsa_p256_sha256).
  ///
  /// [data] - The data to be signed.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature in compact format
  /// as a [Uint8List].
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed.
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
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed.
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  });

  /// Encrypts the provided data using the public key.
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey});

  /// Decrypts the provided data using the public key.
  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey});
}
