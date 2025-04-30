import 'dart:typed_data';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/p256_key_pair.dart';
import '../utility.dart';
import 'key_store/key_store_interface.dart';
import 'key_store/stored_key.dart';
import 'wallet.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';

/// A non-hierarchical wallet implementation that supports multiple key types.
///
/// This wallet can expects a secure [KeyStore] to store key material.
/// It supports signing and verifying messages, and ecrypting/decrypting payloads.
class GenericWallet implements Wallet {
  final KeyStore _keyStore;
  // Optional: Runtime cache for KeyPair objects to avoid reconstruction
  final Map<String, KeyPair> _runtimeCache = {};

  /// Creates a new [GenericWallet] instance backed by a [KeyStore].
  ///
  /// [keyStore] - The KeyStore used to persist key information.
  GenericWallet(this._keyStore);

  @override
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
    } else if (effectiveKeyType == KeyType.ed25519) {
      final (instance, pKeyBytes) = Ed25519KeyPair.generate(id: effectiveKeyId);
      keyPairInstance = instance;
      privateKeyBytes = pKeyBytes;
    } else {
      throw ArgumentError(
          "Unsupported key type for GenericWallet: $effectiveKeyType. Only p256 and ed25519 are supported.");
    }

    final storedKey = StoredKey.fromPrivateKey(
      keyType: effectiveKeyType,
      keyBytes: privateKeyBytes,
    );
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
  /// Returns a [Future] that completes with the X25519 public key as a [Uint8List].
  Future<Uint8List> getX25519PublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    if (keyPair is Ed25519KeyPair) {
      final x25519PublicKey = await keyPair.ed25519KeyToX25519PublicKey();
      return Uint8List.fromList(x25519PublicKey.bytes);
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

  @override
  Future<KeyPair> getKeyPair(String keyId) async {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final storedKey = await _keyStore.get(keyId);
    if (storedKey == null) {
      throw SsiException(
          message: "Key not found in KeyStore: $keyId",
          code: SsiExceptionType.keyNotFound.code);
    }

    if (storedKey.representation != StoredKeyRepresentation.privateKeyBytes) {
      throw SsiException(
          message:
              "KeyStore entry for $keyId is not stored as private key bytes (found ${storedKey.representation}). Incompatible with GenericWallet.",
          code: SsiExceptionType.invalidKeyType.code);
    }

    final keyType = storedKey.keyType;
    final privateKeyBytes = storedKey.privateKeyBytes;
    if (privateKeyBytes == null) {
      throw SsiException(
          message:
              "StoredKey for $keyId has privateKeyBytes representation but null bytes.",
          code: SsiExceptionType.other.code);
    }

    KeyPair keyPair;
    if (keyType == KeyType.p256) {
      keyPair = P256KeyPair.fromPrivateKey(privateKeyBytes);
    } else if (keyType == KeyType.ed25519) {
      keyPair = Ed25519KeyPair.fromPrivateKey(privateKeyBytes);
    } else {
      throw SsiException(
          message: "Unsupported key type retrieved from KeyStore: $keyType",
          code: SsiExceptionType.invalidKeyType.code);
    }

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  void clearCache() {
    _runtimeCache.clear();
  }
}
