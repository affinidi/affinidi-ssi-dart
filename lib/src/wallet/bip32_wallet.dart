import 'dart:typed_data';

import 'package:bip32_plus/bip32_plus.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../key_pair/secp256k1_key_pair.dart';
import '../types.dart';
import 'wallet.dart';

/// A wallet implementation that supports BIP32 key derivation with secp256k1 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using secp256k1 signature scheme,
/// and ecrypting/decrypting payloads.
class Bip32Wallet implements Wallet {
  // Runtime cache for derived KeyPair objects
  final Map<String, Secp256k1KeyPair> _runtimeCache =
      {}; // Keyed by keyId which is equivalent to derivation path
  // Root node derived from seed and used for BIP32 derivation
  final BIP32 _rootNode;

  /// Creates a new [Bip32Wallet] instance.
  /// Use the factory constructor `fromSeed` for typical instantiation.
  Bip32Wallet._(this._rootNode);

  /// Creates a new [Bip32Wallet] using the provided seed.
  ///
  /// [seed] - The master seed bytes. Must be 16, 32, or 64 bytes.
  static Bip32Wallet fromSeed(Uint8List seed) {
    if (seed.length != 16 && seed.length != 32 && seed.length != 64) {
      throw ArgumentError('BIP32 seed length must be 16, 32, or 64 bytes.');
    }
    final node = BIP32.fromSeed(seed);
    return Bip32Wallet._(node);
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(
      String keyId) async {
    final keyPair = _getKeyPair(keyId);
    return keyPair.supportedSignatureSchemes;
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = _getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = _getKeyPair(keyId);
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

    // TODO: thoroughly validate derivation path
    if (!keyId.startsWith('m/')) {
      throw ArgumentError(
          'Invalid derivation path format. Must start with "m/".');
    }

    final effectiveKeyType = keyType ?? KeyType.secp256k1;

    if (effectiveKeyType != KeyType.secp256k1) {
      throw SsiException(
        message:
            'Invalid keyType specified. Bip32Wallet only generates secp256k1 keys. Requested: $keyType',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }

    return _getKeyPair(keyId);
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = _getKeyPair(keyId);
    final keyData = keyPair.publicKey;
    return PublicKey(keyData.id, keyData.bytes, keyData.type);
  }

  @override
  Future<Uint8List> encrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = _getKeyPair(keyId);
    return keyPair.encrypt(data, publicKey: publicKey);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = _getKeyPair(keyId);
    return keyPair.decrypt(data, publicKey: publicKey);
  }

  Secp256k1KeyPair _getKeyPair(String keyId) {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final derivedNode = _rootNode.derivePath(keyId);
    final keyPair = Secp256k1KeyPair(node: derivedNode, id: keyId);

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  /// Clears the runtime cache.
  void clearCache() {
    _runtimeCache.clear();
  }
}
