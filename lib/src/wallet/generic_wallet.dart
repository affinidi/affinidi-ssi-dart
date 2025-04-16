import 'dart:math';
import 'dart:typed_data';

import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/p256_key_pair.dart';
import 'key_store/key_store_interface.dart';
import 'key_store/stored_key.dart';
import 'wallet.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';

class GenericWallet implements Wallet {
  final KeyStore _keyStore;
  static final randomIdLength = 32;

  GenericWallet(KeyStore keyStore) : _keyStore = keyStore;

  @override
  Future<bool> hasKey(String keyId) {
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
    return keyPair.verify(data, signature, signatureScheme: signatureScheme);
  }

  @override
  Future<PublicKey> generateKey({String? keyId, KeyType? keyType}) async {
    if (keyId != null && await _keyStore.contains(keyId)) {
      throw ArgumentError("Key already exists: $keyId");
    }

    keyId ??= randomId();
    keyType ??= KeyType.p256;

    if (keyType == KeyType.p256) {
      final keyPair = P256KeyPair();
      final storedKey = StoredKey(
        type: KeyType.p256,
        key: await keyPair.privateKey,
      );
      await _keyStore.set(keyId, storedKey);

      final keyData = await keyPair.publicKey;
      return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
    } else if (keyType == KeyType.ed25519) {
      final keyPair = Ed25519KeyPair();
      final storedKey = StoredKey(
        type: KeyType.ed25519,
        key: await keyPair.privateKey,
      );
      await _keyStore.set(keyId, storedKey);
      final keyData = await keyPair.publicKey;
      return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
    }

    throw ArgumentError(
        "Only p256 and ed25519 key types are supported for GenericWallet");
  }

  Future<KeyPair> _getKeyPair(String keyId) async {
    final storedKeyPair = await _keyStore.get(keyId);
    if (storedKeyPair == null) {
      throw ArgumentError("Key not found: $keyId");
    }

    final keyType = storedKeyPair.type;
    final privateKeyBytes = storedKeyPair.key;

    if (keyType == KeyType.p256) {
      return P256KeyPair.fromPrivateKey(privateKeyBytes);
    } else if (keyType == KeyType.ed25519) {
      return Ed25519KeyPair.fromPrivateKey(privateKeyBytes);
    }

    throw ArgumentError("Unsupported key type stored for key: $keyId");
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final keyData = await keyPair.publicKey;
    return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
  }

  String randomId() {
    final rnd = Random.secure();
    final buffer = StringBuffer();
    for (var i = 0; i < randomIdLength; i++) {
      buffer.write(rnd.nextInt(16).toRadixString(16));
    }
    return buffer.toString();
  }
}
