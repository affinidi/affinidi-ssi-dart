import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../types.dart';

abstract interface class Wallet {
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
  });

  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
  });

  Future<Uint8List> getPublicKey(String keyId);
  Future<bool> hasKey(String keyId);
  Future<KeyPair> createKeyPair(String keyId, {KeyType? keyType});
  Future<KeyPair> getKeyPair(String keyId);
}
