import 'dart:typed_data';

import 'package:ed25519_hd_key/ed25519_hd_key.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import 'wallet.dart';
import 'stores/seed_store_interface.dart';

/// A wallet implementation that supports BIP32 key derivation with Ed25519 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using Ed25519 signature scheme,
/// and ecrypting/decrypting payloads.
class Bip32Ed25519Wallet implements Wallet {
  final SeedStore? _seedStore;
  // Runtime cache for derived KeyPair objects
  final Map<String, Ed25519KeyPair> _runtimeCache =
      {}; // Keyed by keyId which is equivalent to derivation path
  // Cache for the seed to avoid repeated KeyStore lookups
  Uint8List? _cachedSeed;

  /// Creates a new [Bip32Ed25519Wallet] instance backed by a [SeedStore].
  /// Use the factory constructors `fromSeed` or `fromSeedStore` for typical instantiation.
  Bip32Ed25519Wallet._(this._seedStore);

  /// Creates a new [Bip32Ed25519Wallet] using the provided seed and stores
  /// the seed in the [seedStore]. Overwrites existing seed.
  ///
  /// If no [seedStore] is provided the seed will not be persisted beyond the lifetime of
  /// this wallet instance.
  ///
  /// [seed] - The master seed bytes.
  /// [seedStore] - An optional SeedStore to persist the seed.
  static Future<Bip32Ed25519Wallet> fromSeed(
    Uint8List seed, {
    SeedStore? seedStore,
  }) async {
    if (seedStore != null) {
      await seedStore.setSeed(seed);
    }
    final wallet = Bip32Ed25519Wallet._(seedStore);
    wallet._cachedSeed = seed;
    return wallet;
  }

  /// Creates a new [Bip32Ed25519Wallet] from an existing [SeedStore].
  /// Throws if the seed is not found in the SeedStore.
  ///
  /// [seedStore] - The SeedStore containing the master seed.
  static Future<Bip32Ed25519Wallet> fromSeedStore({
    required SeedStore seedStore,
  }) async {
    final seed = await seedStore.getSeed();
    if (seed == null) {
      throw SsiException(
          message:
              'Seed not found in SeedStore. Cannot create Bip32Ed25519Wallet from this SeedStore.',
          code: SsiExceptionType.seedNotFound.code);
    }
    final wallet = Bip32Ed25519Wallet._(seedStore);
    wallet._cachedSeed = seed;
    return wallet;
  }

  Future<Uint8List> _getSeed() async {
    if (_cachedSeed != null) return _cachedSeed!;
    final seed = await _seedStore?.getSeed();
    if (seed == null) {
      throw SsiException(
          message: 'Seed not found in SeedStore during operation.',
          code: SsiExceptionType.seedNotFound.code);
    }
    _cachedSeed = seed;
    return seed;
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(
      String keyId) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.supportedSignatureSchemes;
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await getKeyPair(keyId);
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

    // Check runtime cache first
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    // Derive the key
    final seed = await _getSeed();
    final derivedData = await ED25519_HD_KEY.derivePath(keyId, seed);
    final keyPair =
        Ed25519KeyPair.fromSeed(Uint8List.fromList(derivedData.key), id: keyId);
    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
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
  /// Returns a [Future] that completes with the X25519 public key as a [Uint8List].
  Future<Uint8List> getX25519PublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    final x25519PublicKey = await keyPair.ed25519KeyToX25519PublicKey();
    return Uint8List.fromList(x25519PublicKey.bytes);
  }

  @override
  Future<Uint8List> encrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.encrypt(data, publicKey: publicKey);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.decrypt(data, publicKey: publicKey);
  }

  @override
  Future<Ed25519KeyPair> getKeyPair(String keyId) async {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final seed = await _getSeed();
    final derivedData = await ED25519_HD_KEY.derivePath(keyId, seed);
    final keyPair =
        Ed25519KeyPair.fromSeed(Uint8List.fromList(derivedData.key), id: keyId);

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  void clearCache() {
    _runtimeCache.clear();
    _cachedSeed = null;
  }
}
