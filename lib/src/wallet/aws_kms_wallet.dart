import 'dart:typed_data';

import 'package:affinidi_ssi/src/key_pair/key_pair.dart';

import 'wallet.dart';
import '../types.dart';

// TODO: Implement AWS KMS wallet

class AwsKmsWallet implements Wallet {
  @override
  Future<bool> hasKey(String keyId) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<KeyPair> createKeyPair(String keyId, {KeyType? keyType}) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> getPublicKey(String keyId) {
    throw UnimplementedError();
  }

  @override
  Future<KeyPair> getKeyPair(String keyId) async {
    throw UnimplementedError();
  }
}
