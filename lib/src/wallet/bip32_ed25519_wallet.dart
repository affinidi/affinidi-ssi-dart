import 'dart:typed_data';

import 'package:ed25519_hd_key/ed25519_hd_key.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../utility.dart';
import 'deterministic_wallet.dart';
import 'stores/seed_store_interface.dart';

/// A wallet implementation that supports BIP32 key derivation with Ed25519 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using Ed25519 signature scheme,
/// and ecrypting/decrypting payloads.
class Bip32Ed25519Wallet implements DeterministicWallet {
  final KeyStore _keyStore;
  // Runtime cache for derived KeyPair objects
  final Map<String, Ed25519KeyPair> _runtimeCache = {};
  // Cache for the seed to avoid repeated KeyStore lookups
  Uint8List? _cachedSeed;

  /// Creates a new [Bip32Ed25519Wallet] instance backed by a [KeyStore].
  /// The KeyStore *must* contain a seed set via `setSeed` or be populated
  /// using the `fromSeed` factory.
  ///
  /// [keyStore] - The KeyStore used to persist key derivation paths and the master seed.
  Bip32Ed25519Wallet(this._keyStore);

  /// Creates a new [Bip32Ed25519Wallet] using the provided seed and stores
  /// the seed in the [keyStore]. Overwrites existing seed.
  ///
  /// [seed] - The master seed bytes.
  /// [keyStore] - The KeyStore to use.
  static Future<Bip32Ed25519Wallet> fromSeed(
      Uint8List seed, KeyStore keyStore) async {
    await keyStore.setSeed(seed);
    final wallet = Bip32Ed25519Wallet(keyStore);
    wallet._cachedSeed = seed;
    return wallet;
  }

  /// Creates a new [Bip32Ed25519Wallet] from an existing [KeyStore].
  /// Throws if the seed is not found in the KeyStore.
  ///
  /// [keyStore] - The KeyStore containing the seed and key mappings.
  static Future<Bip32Ed25519Wallet> fromKeyStore(KeyStore keyStore) async {
    final seed = await keyStore.getSeed();
    if (seed == null) {
      throw SsiException(
          message:
              'Seed not found in KeyStore. Cannot create Bip32Ed25519Wallet from this KeyStore.',
          code: SsiExceptionType.seedNotFound.code);
    }
    final wallet = Bip32Ed25519Wallet(keyStore);
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
    // TODO: thoroughly validate derivation path. If not fully hardened did peer fails
    if (!derivationPath.startsWith('m/')) {
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

    final effectiveKeyId = keyId ?? randomId();

    if (await _keyStore.contains(effectiveKeyId)) {
      // Key ID exists, ensure it points to the same path or handle conflict
      final existingStoredKey = await _keyStore.get(effectiveKeyId);
      if (existingStoredKey != null &&
          existingStoredKey.representation ==
              StoredKeyRepresentation.derivationPath &&
          existingStoredKey.derivationPath == derivationPath &&
          existingStoredKey.keyType == effectiveKeyType) {
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
    final derivedData = await ED25519_HD_KEY.derivePath(derivationPath, seed);
    final keyPair = Ed25519KeyPair.fromSeed(Uint8List.fromList(derivedData.key),
        id: effectiveKeyId);
    _runtimeCache[effectiveKeyId] = keyPair;
    return keyPair;
  }

  @override
  Future<KeyPair> generateKey({String? keyId, KeyType? keyType}) {
    // Bip32Ed25519Wallet requires a derivation path.
    // Throw an error if the base generateKey (without path) is called.
    throw UnsupportedError(
      'Bip32Ed25519Wallet requires a derivation path. Use deriveKey instead.',
    );
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final keyData = keyPair.publicKey;
    return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
  }

  /// Retrieves the X25519 public key corresponding to the given Ed25519 key ID.
  ///
  /// This is used for cryptographic operations like ECDH key agreement.
  /// Throws an [SsiException] if the key is invalid or not found.
  ///
  /// [keyId] - The identifier of the Ed25519 key pair.
  ///
  /// Returns a [Future] that completes with the X25519 public key as a [Uint8List].
  Future<Uint8List> getX25519PublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final x25519PublicKey = await keyPair.ed25519KeyToX25519PublicKey();
    return Uint8List.fromList(x25519PublicKey.bytes);
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

    final storedKey = await _keyStore.get(keyId);
    if (storedKey == null) {
      throw SsiException(
          message: "Key not found in KeyStore: $keyId",
          code: SsiExceptionType.keyNotFound.code);
    }

    if (storedKey.representation != StoredKeyRepresentation.derivationPath) {
      throw SsiException(
          message:
              "KeyStore entry for $keyId is not stored as a derivation path (found ${storedKey.representation}). Incompatible with Bip32Ed25519Wallet.",
          code: SsiExceptionType.invalidKeyType.code);
    }
    if (storedKey.keyType != KeyType.ed25519) {
      throw SsiException(
          message:
              "KeyStore entry for $keyId indicates type ${storedKey.keyType}, but Bip32Ed25519Wallet requires ed25519.",
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

    final derivedData = await ED25519_HD_KEY.derivePath(derivationPath, seed);
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
