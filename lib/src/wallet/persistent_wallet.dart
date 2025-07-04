import 'dart:typed_data';

import '../../ssi.dart';
import '../utility.dart';

/// A non-hierarchical wallet implementation that supports multiple key types.
///
/// This wallet expects a secure [KeyStore] to store key material.
/// It supports signing and verifying messages, and ecrypting/decrypting payloads.
class PersistentWallet implements Wallet {
  final KeyStore _keyStore;

  // Optional: Runtime cache for KeyPair objects to avoid reconstruction
  final Map<String, KeyPair> _runtimeCache = {};

  /// Creates a new [PersistentWallet] instance backed by a [KeyStore].
  ///
  /// keyStore - The KeyStore used to persist key information.
  PersistentWallet(this._keyStore);

  /// Checks if a key with the specified identifier exists in the wallet.
  ///
  /// [keyId] - The identifier of the key to check.
  ///
  /// Returns a [Future] that completes with `true` if the key exists,
  /// `false` otherwise.
  Future<bool> hasKey(String keyId) {
    // Check cache first, then keystore
    if (_runtimeCache.containsKey(keyId)) return Future.value(true);
    return _keyStore.contains(keyId);
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
    return keyPair.verify(data, signature, signatureScheme: signatureScheme);
  }

  @override
  Future<KeyPair> generateKey({
    String? keyId,
    KeyType? keyType,
  }) async {
    final effectiveKeyId = keyId ?? randomId();
    if (await _keyStore.contains(effectiveKeyId)) {
      // Found key in key store
      return getKeyPair(effectiveKeyId);
    }

    final effectiveKeyType = keyType ?? KeyType.p256;

    KeyPair keyPairInstance;
    Uint8List privateKeyBytes;

    if (effectiveKeyType == KeyType.p256) {
      final (instance, pKeyBytes) = P256KeyPair.generate(id: effectiveKeyId);
      keyPairInstance = instance;
      privateKeyBytes = pKeyBytes;
    } else if (effectiveKeyType == KeyType.p384) {
      final (instance, pKeyBytes) = P384KeyPair.generate(id: effectiveKeyId);
      keyPairInstance = instance;
      privateKeyBytes = pKeyBytes;
    } else if (effectiveKeyType == KeyType.p521) {
      final (instance, pKeyBytes) = P521KeyPair.generate(id: effectiveKeyId);
      keyPairInstance = instance;
      privateKeyBytes = pKeyBytes;
    } else if (effectiveKeyType == KeyType.ed25519) {
      final (instance, pKeyBytes) = Ed25519KeyPair.generate(id: effectiveKeyId);
      keyPairInstance = instance;
      privateKeyBytes = pKeyBytes;
    } else {
      throw ArgumentError(
          'Unsupported key type for PersistentWallet: $effectiveKeyType. Only p256, p384, p521, and ed25519 are supported.');
    }

    final storedKey =
        StoredKey(keyType: effectiveKeyType, privateKeyBytes: privateKeyBytes);
    await _keyStore.set(effectiveKeyId, storedKey);
    _runtimeCache[effectiveKeyId] = keyPairInstance;

    return keyPairInstance;
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    final keyData = keyPair.publicKey;
    return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
  }

  /// Retrieves the X25519 public key corresponding to the given Ed25519 key ID.
  ///
  /// This is used for cryptographic operations like ECDH key agreement.
  /// Throws an [SsiException] if the key is not an Ed25519 key or not found.
  ///
  /// [keyId] - The identifier of the Ed25519 key pair.
  ///
  /// Returns a [Future] that completes with the X25519 public key as a [PublicKey].
  Future<PublicKey> getX25519PublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    if (keyPair is Ed25519KeyPair) {
      final x25519PublicKey = await keyPair.ed25519KeyToX25519PublicKey();
      return x25519PublicKey;
    } else {
      // P256KeyPair and other potential types do not have a direct X25519 equivalent
      throw SsiException(
        message:
            'getX25519PublicKey is only supported for Ed25519 keys. Key $keyId is of type ${keyPair.runtimeType}.',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }
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

  /// Retrieves the KeyPair object for the specified key identifier.
  ///
  /// [keyId] - The identifier of the key.
  /// Returns a [Future] that completes with the [KeyPair].
  Future<KeyPair> getKeyPair(String keyId) async {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final storedKey = await _keyStore.get(keyId);
    if (storedKey == null) {
      throw SsiException(
          message: 'Key not found in KeyStore: $keyId',
          code: SsiExceptionType.keyNotFound.code);
    }

    final keyType = storedKey.keyType;
    final privateKeyBytes = storedKey.privateKeyBytes;

    KeyPair keyPair;
    if (keyType == KeyType.p256) {
      keyPair = P256KeyPair.fromPrivateKey(privateKeyBytes);
    } else if (keyType == KeyType.p384) {
      keyPair = P384KeyPair.fromPrivateKey(privateKeyBytes);
    } else if (keyType == KeyType.p521) {
      keyPair = P521KeyPair.fromPrivateKey(privateKeyBytes);
    } else if (keyType == KeyType.ed25519) {
      keyPair = Ed25519KeyPair.fromPrivateKey(privateKeyBytes);
    } else {
      throw SsiException(
          message: 'Unsupported key type retrieved from KeyStore: $keyType',
          code: SsiExceptionType.invalidKeyType.code);
    }

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  /// Clears the runtime cache.
  void clearCache() {
    _runtimeCache.clear();
  }
}
