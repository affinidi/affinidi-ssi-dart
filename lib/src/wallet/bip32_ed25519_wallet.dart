import 'dart:typed_data';

import 'package:ed25519_hd_key/ed25519_hd_key.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import 'wallet.dart';

/// A wallet implementation that supports BIP32 key derivation with Ed25519 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using Ed25519 signature scheme,
/// and ecrypting/decrypting payloads.
class Bip32Ed25519Wallet implements Wallet {
  // Runtime cache for derived KeyPair objects
  final Map<String, Ed25519KeyPair> _runtimeCache =
      {}; // Keyed by keyId which is equivalent to derivation path
  // Seed used for BIP32 derivation
  final Uint8List _seed;

  /// Creates a new [Bip32Ed25519Wallet] instance.
  /// Use the factory constructor `fromSeed` for typical instantiation.
  Bip32Ed25519Wallet._(this._seed);

  /// Creates a new [Bip32Ed25519Wallet] using the provided seed.
  ///
  /// [seed] - The master seed bytes.
  static Bip32Ed25519Wallet fromSeed(Uint8List seed) {
    return Bip32Ed25519Wallet._(seed);
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(
      String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.supportedSignatureSchemes;
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.verify(
      data,
      signature,
      signatureScheme: signatureScheme,
    );
  }

  @override
  Future<KeyPair> generateKey({String? keyId, KeyType? keyType}) async {
    if (keyId == null) {
      throw ArgumentError(
          'keyId is required for Bip32Wallet as it defines the derivation path');
    }

    // TODO: thoroughly validate derivation path. If not fully hardened did peer fails
    if (!keyId.startsWith('m/')) {
      throw ArgumentError(
          'Invalid derivation path format. Must start with "m/".');
    }

    final effectiveKeyType = keyType ?? KeyType.ed25519;
    if (effectiveKeyType != KeyType.ed25519) {
      throw SsiException(
        message:
            'Invalid keyType specified. Bip32Ed25519Wallet only generates ed25519 keys.',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }
    return _getKeyPair(keyId);
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final keyData = keyPair.publicKey;
    return PublicKey(keyData.id, keyData.bytes, keyData.type);
  }

  /// Retrieves the X25519 public key corresponding to the key at the given
  /// keyId (derivation path).
  ///
  /// This is used for cryptographic operations like ECDH key agreement.
  /// Throws an [SsiException] if the key is invalid or not found.
  ///
  /// [keyId] - The derivation path of the Ed25519 key pair.
  ///
  /// Returns a [Future] that completes with the X25519 public key as a [PublicKey].
  Future<PublicKey> getX25519PublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final x25519PublicKey = await keyPair.ed25519KeyToX25519PublicKey();
    return x25519PublicKey;
  }

  @override
  Future<Uint8List> encrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.encrypt(data, publicKey: publicKey);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.decrypt(data, publicKey: publicKey);
  }

  Future<Ed25519KeyPair> _getKeyPair(String keyId) async {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final derivedData = await ED25519_HD_KEY.derivePath(keyId, _seed);
    final keyPair =
        Ed25519KeyPair.fromSeed(Uint8List.fromList(derivedData.key), id: keyId);

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  /// Clears the runtime cache.
  void clearCache() {
    _runtimeCache.clear();
  }
}
