import 'dart:typed_data';

import '../../ssi.dart';

/// Interface for a wallet
abstract interface class Wallet {
  /// Returns a [Future] that completes with a list of the [SignatureScheme]s
  /// supported by a key pair key pair.
  ///
  /// [keyId] - The identifier of the key. For deterministic wallets (e.g., BIP32),
  ///           this is the derivation path.
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(String keyId);

  /// Signs the data using the specified key.
  ///
  /// [data] - The data to be signed.
  /// [keyId] - The identifier of the key to use for signing.
  /// [signatureScheme] - The signature scheme to use. If null defaults to:
  /// - [SignatureScheme.ecdsa_secp256k1_sha256] for [Secp256k1KeyPair]
  /// - [SignatureScheme.ed25519] for [Ed25519KeyPair]
  /// - [SignatureScheme.ecdsa_p256_sha256] for [P256KeyPair]
  ///
  /// [keyId] - The identifier of the key to use for signing. For deterministic
  ///           wallets (e.g., BIP32), this is the derivation path.
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
  /// [keyId] - The identifier of the key to use for verification. For deterministic
  ///           wallets (e.g., BIP32), this is the derivation path.
  /// [signatureScheme] - The signature scheme to use. If null defaults to:
  /// - [SignatureScheme.ecdsa_secp256k1_sha256] for [Secp256k1KeyPair]
  /// - [SignatureScheme.ed25519] for [Ed25519KeyPair]
  /// - [SignatureScheme.ecdsa_p256_sha256] for [P256KeyPair]
  ///
  /// [keyId] - The identifier of the key to use for verification. For deterministic
  ///           wallets (e.g., BIP32), this is the derivation path.
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
  /// [keyId] - The identifier of the key. For deterministic wallets (e.g., BIP32),
  ///           this is the derivation path.
  ///
  /// Returns a [Future] that completes with the public key as a [PublicKey].
  ///
  /// Throws an [SsiException] if the operation fails.
  Future<PublicKey> getPublicKey(String keyId);

  /// Generates a new key pair with the specified identifier.
  ///
  /// [keyId] - The identifier for the new key pair. While optional in the interface,
  ///           some implementations, particularly deterministic wallets (e.g., BIP32),
  ///           may require this to be provided as the derivation path. If not provided,
  ///           implementations might generate a random ID or throw an error if an ID
  ///           is required.
  /// [keyType] - The type of key to create. If not specified, the implementation
  /// should use a default key type.
  ///
  /// Returns a [Future] that completes with the newly created [KeyPair].
  /// Throws an [SsiException] if a keyId is null or empty or
  /// if key creation fails.
  Future<KeyPair> generateKey({String? keyId, KeyType? keyType});

  /// Encrypts data using the specified key.
  ///
  /// [data] - The data to be encrypted.
  /// [keyId] - The identifier of the key to use for encryption. For deterministic
  ///           wallets (e.g., BIP32), this is the derivation path.
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
  });

  /// Decrypts data using the specified key.
  ///
  /// [data] - The encrypted data to be decrypted.
  /// [keyId] - The identifier of the key to use for decryption. For deterministic
  ///           wallets (e.g., BIP32), this is the derivation path.
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
  });
}
