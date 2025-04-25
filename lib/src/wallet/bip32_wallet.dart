import 'dart:math';
import 'dart:typed_data';

import 'package:bip32/bip32.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../key_pair/secp256k1_key_pair.dart';
import '../types.dart';
import 'deterministic_wallet.dart';
import 'key_store/key_store_interface.dart';
import 'key_store/stored_key.dart';

/// A wallet implementation that supports BIP32 key derivation with secp256k1 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using secp256k1 signature scheme,
/// and ecrypting/decrypting payloads.
class Bip32Wallet implements DeterministicWallet {
  final KeyStore _keyStore;
  // Runtime cache for derived KeyPair objects
  final Map<String, Secp256k1KeyPair> _runtimeCache = {};
  // Cache for the seed to avoid repeated KeyStore lookups
  // TODO: cache the root node instead
  Uint8List? _cachedSeed;

  /// Creates a new [Bip32Wallet] instance backed by a [KeyStore].
  /// The KeyStore *must* contain a seed set via `setSeed` or be populated
  /// using the `fromSeed` factory.
  ///
  /// [keyStore] - The KeyStore used to persist key derivation paths and the master seed.
  Bip32Wallet(this._keyStore);

  /// Creates a new [Bip32Wallet] using the provided seed and stores
  /// the seed in the [keyStore]. Overwrites existing seed.
  ///
  /// [seed] - The master seed bytes. Must be 16, 32, or 64 bytes.
  /// [keyStore] - The KeyStore to use.
  static Future<Bip32Wallet> fromSeed(Uint8List seed, KeyStore keyStore) async {
    if (seed.length != 16 && seed.length != 32 && seed.length != 64) {
      throw ArgumentError('BIP32 seed length must be 16, 32, or 64 bytes.');
    }
    await keyStore.setSeed(seed);
    final wallet = Bip32Wallet(keyStore);
    wallet._cachedSeed = seed;
    return wallet;
  }

  /// Creates a new [Bip32Wallet] from an existing [KeyStore].
  /// Throws if the seed is not found in the KeyStore.
  ///
  /// [keyStore] - The KeyStore containing the seed and key mappings.
  static Future<Bip32Wallet> fromKeyStore(KeyStore keyStore) async {
    final seed = await keyStore.getSeed();
    if (seed == null) {
      throw SsiException(
          message:
              'Seed not found in KeyStore. Cannot create Bip32Wallet from this KeyStore.',
          code: SsiExceptionType.seedNotFound.code);
    }
    final wallet = Bip32Wallet(keyStore);
    wallet._cachedSeed = seed;
    return wallet;
  }

  Future<Uint8List> _getSeed() async {
    if (_cachedSeed != null) return _cachedSeed!;
    final seed = await _keyStore.getSeed();
    if (seed == null) {
      throw SsiException(
          message: 'Seed not found in KeyStore during operation.',
          code: SsiExceptionType.seedNotFound.code);
    }
    _cachedSeed = seed;
    return seed;
  }

  @override
  Future<bool> hasKey(String keyId) {
    if (_runtimeCache.containsKey(keyId)) return Future.value(true);
    return _keyStore.contains(keyId);
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
  Future<KeyPair> deriveKey({
    String? keyId,
    KeyType? keyType,
    required String derivationPath,
  }) async {
    // TODO: thoroughly validate derivation path
    if (!derivationPath.startsWith('m/')) {
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

    final effectiveKeyId = keyId ?? _randomId();

    if (await _keyStore.contains(effectiveKeyId)) {
      // Key ID exists, ensure it points to the same path or handle conflict
      final existingStoredKey = await _keyStore.get(effectiveKeyId);
      if (existingStoredKey != null &&
          existingStoredKey.representation ==
              StoredKeyRepresentation.derivationPath &&
          existingStoredKey.derivationPath == derivationPath &&
          existingStoredKey.keyType == effectiveKeyType) {
        // Key exists and matches, return the existing KeyPair
        return _getKeyPair(effectiveKeyId);
      } else {
        throw ArgumentError(
            "Key ID $effectiveKeyId already exists in KeyStore but with incompatible data.");
      }
    }

    final storedKey = StoredKey.fromDerivationPath(
      keyType: effectiveKeyType,
      path: derivationPath,
    );
    await _keyStore.set(effectiveKeyId, storedKey);

    final seed = await _getSeed();
    final rootNode = BIP32.fromSeed(seed);
    final derivedNode = rootNode.derivePath(derivationPath);
    final keyPair = Secp256k1KeyPair(node: derivedNode);
    _runtimeCache[effectiveKeyId] = keyPair; // Cache the new keypair
    return keyPair; // Return the newly derived KeyPair
  }

  @override
  Future<KeyPair> generateKey({String? keyId, KeyType? keyType}) {
    // Bip32Wallet requires a derivation path.
    // Throw an error if the base generateKey (without path) is called.
    throw UnsupportedError(
      'Bip32Wallet requires a derivation path. Use deriveKey instead.',
    );
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final keyData = await keyPair.publicKey;
    return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
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

    final storedKey = await _keyStore.get(keyId);
    if (storedKey == null) {
      throw SsiException(
          message: "Key not found in KeyStore: $keyId",
          code: SsiExceptionType.keyNotFound.code);
    }

    if (storedKey.representation != StoredKeyRepresentation.derivationPath) {
      throw SsiException(
          message:
              "KeyStore entry for $keyId is not stored as a derivation path (found ${storedKey.representation}). Incompatible with Bip32Wallet.",
          code: SsiExceptionType.invalidKeyType.code);
    }
    if (storedKey.keyType != KeyType.secp256k1) {
      throw SsiException(
          message:
              "KeyStore entry for $keyId indicates type ${storedKey.keyType}, but Bip32Wallet requires secp256k1.",
          code: SsiExceptionType.invalidKeyType.code);
    }

    final derivationPath = storedKey.derivationPath;
    if (derivationPath == null) {
      throw SsiException(
          message:
              "StoredKey for $keyId has derivationPath representation but null path.",
          code: SsiExceptionType.other.code);
    }

    final seed = await _getSeed();

    final rootNode = BIP32.fromSeed(seed);
    final derivedNode = rootNode.derivePath(derivationPath);
    final keyPair = Secp256k1KeyPair(node: derivedNode);

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  String _randomId() {
    final rnd = Random.secure();
    return List.generate(32, (idx) => rnd.nextInt(16).toRadixString(16)).join();
  }

  void clearCache() {
    _runtimeCache.clear();
    _cachedSeed = null;
  }
}
