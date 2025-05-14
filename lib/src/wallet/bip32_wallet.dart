import 'dart:typed_data';

import 'package:bip32_plus/bip32_plus.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../key_pair/secp256k1_key_pair.dart';
import '../types.dart';
import 'stores/seed_store_interface.dart';
import 'wallet.dart';

/// A wallet implementation that supports BIP32 key derivation with secp256k1 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using secp256k1 signature scheme,
/// and ecrypting/decrypting payloads.
class Bip32Wallet implements Wallet {
  final SeedStore? _seedStore;
  // Runtime cache for derived KeyPair objects
  final Map<String, Secp256k1KeyPair> _runtimeCache =
      {}; // Keyed by keyId which is equivalent to derivation path
  // Cache for the root node to avoid repeated SeedStore lookups and BIP32 derivation
  BIP32? _cachedRootNode;

  /// Creates a new [Bip32Wallet] instance backed by a [SeedStore].
  /// Use the factory constructors `fromSeed` or `fromSeedStore` for typical instantiation.
  ///
  /// [_seedStore] - The KeyStore used to persist key derivation paths and the master seed.
  Bip32Wallet._(this._seedStore);

  /// Creates a new [Bip32Wallet] using the provided seed and stores
  /// the seed in the [seedStore]. Overwrites existing seed.
  ///
  /// If no [seedStore] is provided the seed will not be persisted beyond the lifetime of
  /// this wallet instance.
  ///
  /// [seed] - The master seed bytes. Must be 16, 32, or 64 bytes.
  /// [seedStore] - An optional SeedStore to persist the seed.
  static Future<Bip32Wallet> fromSeed(
    Uint8List seed, {
    SeedStore? seedStore,
  }) async {
    if (seed.length != 16 && seed.length != 32 && seed.length != 64) {
      throw ArgumentError('BIP32 seed length must be 16, 32, or 64 bytes.');
    }
    if (seedStore != null) {
      await seedStore.setSeed(seed);
    }
    final wallet = Bip32Wallet._(seedStore);
    wallet._cachedRootNode = BIP32.fromSeed(seed);
    return wallet;
  }

  /// Creates a new [Bip32Wallet] from an existing [SeedStore].
  /// Throws if the seed is not found in the SeedStore.
  ///
  /// [seedStore] - The SeedStore containing the master seed.
  static Future<Bip32Wallet> fromSeedStore({
    required SeedStore seedStore,
  }) async {
    final seed = await seedStore.getSeed();
    if (seed == null) {
      throw SsiException(
          message:
              'Seed not found in SeedStore. Cannot create Bip32Wallet from this SeedStore.',
          code: SsiExceptionType.seedNotFound.code);
    }
    final wallet = Bip32Wallet._(seedStore);
    wallet._cachedRootNode = BIP32.fromSeed(seed);
    return wallet;
  }

  Future<BIP32> _getRootNode() async {
    if (_cachedRootNode != null) return _cachedRootNode!;
    final seed = await _seedStore?.getSeed();
    if (seed == null) {
      throw SsiException(
          message:
              'Root node not cached and seed not found in SeedStore during operation.',
          code: SsiExceptionType.seedNotFound.code);
    }
    _cachedRootNode = BIP32.fromSeed(seed);
    return _cachedRootNode!;
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
    final keyPair = await _getKeyPair(keyId);
    final keyData = keyPair.publicKey;
    return PublicKey(keyData.id, keyData.bytes, keyData.type);
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

  Future<Secp256k1KeyPair> _getKeyPair(String keyId) async {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final rootNode = await _getRootNode();
    final derivedNode = rootNode.derivePath(keyId);
    final keyPair = Secp256k1KeyPair(node: derivedNode, id: keyId);

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  /// Clears the runtime cache and cached seed.
  void clearCache() {
    _runtimeCache.clear();
    _cachedRootNode = null;
  }
}
