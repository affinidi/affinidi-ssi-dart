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
  Future<KeyPair> deriveKeyPair(String keyId);
  Future<KeyPair> getKeyPair(String keyId);

  // NOTE: this particular implentation of the wallet hardcodes the algorithm used. Will we need an implementation where the algorithm is configurable? In which case we need to update the interface
  Future<KeyType> getKeyType();
  Future<HashingAlgorithm> getHashingAlgorithm();
  Future<AlgorithmSuite> getAlgorithmSuite();
}
