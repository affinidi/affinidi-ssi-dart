import 'dart:typed_data';

import '../key_pair/p256_key_pair.dart';
import 'key_store/in_memory_key_store.dart';
import 'key_store/key_store_interface.dart';
import 'wallet.dart';
import '../key_pair/key_pair.dart';
import '../types.dart';

class GenericWallet implements Wallet {
  final KeyStore _keyStore;

  GenericWallet([KeyStore? keyStore])
      : _keyStore = keyStore ?? InMemoryKeyStore();

  @override
  Future<bool> hasKey(String keyId) {
    return _keyStore.contains(keyId);
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
  Future<KeyPair> createKeyPair(String keyId, {KeyType? keyType}) async {
    if (await _keyStore.contains(keyId)) {
      throw ArgumentError("Key already exists: $keyId");
    }
    if (keyType == KeyType.p256) {
      final keyPair = Future.value(P256KeyPair.create(keyId: keyId));
      // TODO: Get value from key pair
      _keyStore.set(keyId, value);
      return keyPair;
    }
    throw ArgumentError("Only p256 key type is supported for GenericWallet");
  }

  @override
  Future<KeyPair> getKeyPair(String keyId) async {
    final storedKeyPair = await _keyStore.get(keyId);
    if (storedKeyPair != null) {
      throw ArgumentError("Key not found: $keyId");
    }
    // TODO: deserialize key pair
  }

  @override
  Future<Uint8List> getPublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.publicKey;
  }
}
