import 'dart:typed_data';

import 'package:bip32/bip32.dart';

import 'key_pair.dart';
import '../types.dart';

class Secp256k1KeyPair implements KeyPair {
  final String _keyId;
  final BIP32 _node;

  Secp256k1KeyPair({required BIP32 node, required String keyId})
      : _node = node,
        _keyId = keyId;

  @override
  Future<String> getKeyId() async => _keyId;

  @override
  Future<Uint8List> getPublicKey() async => _node.publicKey;

  @override
  Future<KeyType> getKeyType() async => KeyType.secp256k1;

  @override
  Future<AlgorithmSuite> getAlgorithmSuite() async => AlgorithmSuite.es256k;

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  }) async {
    if (hashingAlgorithm != HashingAlgorithm.sha256) {
      throw ArgumentError(
          "Unsupported hashing algorithm. Currently only SHA-256 is supported with secp256k1");
    }
    final digest = KeyPair.getDigest(
      data,
      hashingAlgorithm: hashingAlgorithm,
    );
    return _node.sign(digest);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  }) async {
    final digest = KeyPair.getDigest(
      data,
      hashingAlgorithm: hashingAlgorithm,
    );
    return _node.verify(digest, signature);
  }

  BIP32 getBip32Node() => _node;
}
