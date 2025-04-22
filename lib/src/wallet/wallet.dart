import 'dart:typed_data';

import '../key_pair/public_key.dart';
import '../types.dart';

/// Interface for a wallet
abstract interface class Wallet {
  /// Returns a [Future] that completes with a list of the [SignatureScheme]s
  /// supported by a key pair key pair.
  ///
  /// [keyId] - The identifier of the key to use for signing.
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(String keyId);

  /// Signs the data using the specified key.
  ///
  /// [data] - The data to be signed.
  /// [keyId] - The identifier of the key to use for signing.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature as a [Uint8List].
  ///
  /// Throws an [SsiException] if signing fails.
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  });

  /// Verifies a signature using the specified key.
  ///
  /// [data] - The data that was signed.
  /// [signature] - The signature to verify.
  /// [keyId] - The identifier of the key to use for verification.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with `true` if the signature is valid,
  /// `false` otherwise.
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  });

  /// Retrieves the public key for the specified key identifier.
  ///
  /// [keyId] - The identifier of the key.
  ///
  /// Returns a [Future] that completes with the public key as a [PublicKey].
  ///
  /// Throws an [SsiException] if the operation fails.
  Future<PublicKey> getPublicKey(String keyId);

  /// Checks if a key with the specified identifier exists in the wallet.
  ///
  /// [keyId] - The identifier of the key to check.
  ///
  /// Returns a [Future] that completes with `true` if the key exists,
  /// `false` otherwise.
  Future<bool> hasKey(String keyId);

  /// Generates a new key pair with the specified identifier.
  ///
  /// [keyId] - The identifier for the new key pair.
  /// [keyType] - The type of key to create. If not specified, the implementation
  /// should use a default key type.
  ///
  /// Returns a [Future] that completes with the newly created [KeyPair].
  ///
  /// Throws an [SsiException] if a keyId is null or empty or
  /// if key creation fails.
  Future<PublicKey> generateKey({String? keyId, KeyType? keyType});
}
