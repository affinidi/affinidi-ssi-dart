import 'dart:typed_data';

import 'package:bip32/bip32.dart';

import '../digest_utils.dart';
import '../types.dart';
import 'key_pair.dart';

class Secp256k1KeyPair implements KeyPair {
  final String _keyId;
  final BIP32 _node;

  Secp256k1KeyPair({
    required BIP32 node,
    required String keyId,
  })  : _node = node,
        _keyId = keyId;

  @override
  Future<String> get id => Future.value(_keyId);

  @override
  Future<Uint8List> get publicKey => Future.value(_node.publicKey);

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.secp256k1);

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.es256k;
    if (signatureScheme != SignatureScheme.es256k) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only es256k is supported with secp256k1");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.sign(digest);
  }

  @override
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.es256k;
    if (signatureScheme != SignatureScheme.es256k) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only es256k is supported with secp256k1");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.verify(digest, signature);
  }

  BIP32 getBip32Node() => _node;

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.es256k];
}
