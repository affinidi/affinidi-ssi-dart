import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import '../types.dart';

abstract interface class KeyPair {
  Future<Uint8List> getPublicKey();
  Future<KeyType> getKeyType();
  Future<AlgorithmSuite> getAlgorithmSuite();
  Future<String> getKeyId();

  Future<Uint8List> sign(
    Uint8List data, {
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  });

  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  });

  static final Map<HashingAlgorithm, Digest> _digests = {
    HashingAlgorithm.sha256: Digest('SHA-256'),
    HashingAlgorithm.sha512: Digest('SHA-512'),
  };

  static Uint8List getDigest(
    Uint8List data, {
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  }) {
    return _digests[hashingAlgorithm]!.process(data);
  }
}
