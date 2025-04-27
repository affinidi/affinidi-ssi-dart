import 'dart:typed_data';

import 'package:ssi/src/key_pair/_ecdh_profile.dart';

import '../key_pair/key_pair.dart';
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
  /// [signatureScheme] - The signature scheme to use. If null defaults to:
  /// - [SignatureScheme.ecdsa_secp256k1_sha256] for [Secp256k1KeyPair]
  /// - [SignatureScheme.eddsa_sha512] for [Ed25519KeyPair]
  /// - [SignatureScheme.ecdsa_p256_sha256] for [P256KeyPair]
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
  /// [signatureScheme] - The signature scheme to use. If null defaults to:
  /// - [SignatureScheme.ecdsa_secp256k1_sha256] for [Secp256k1KeyPair]
  /// - [SignatureScheme.eddsa_sha512] for [Ed25519KeyPair]
  /// - [SignatureScheme.ecdsa_p256_sha256] for [P256KeyPair]
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
  Future<KeyPair> generateKey({String? keyId, KeyType? keyType});

  /// Encrypts data using the specified key.
  ///
  /// [data] - The data to be encrypted.
  /// [keyId] - The identifier of the key to use for encryption.
  /// [publicKey] - Optional public key of the recipient. If not provided,
  ///               an ephemeral key pair might be generated depending on the
  ///               underlying key pair implementation.
  ///
  /// Returns a [Future] that completes with the encrypted data as a [Uint8List].
  ///
  /// Throws an [SsiException] if encryption fails.
  Future<Uint8List> encrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
    ECDHProfile? ecdhProfile,
  });

  /// Decrypts data using the specified key.
  ///
  /// [data] - The encrypted data to be decrypted.
  /// [keyId] - The identifier of the key to use for decryption.
  /// [publicKey] - Optional public key of the sender. May be required by some
  ///               underlying key pair implementations, especially if an
  ///               ephemeral key was not used during encryption.
  ///
  /// Returns a [Future] that completes with the decrypted data as a [Uint8List].
  ///
  /// Throws an [SsiException] if decryption fails.
  Future<Uint8List> decrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
    ECDHProfile? ecdhProfile,
  });
}
