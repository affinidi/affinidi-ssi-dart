import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import 'key_pair.dart';
import '../digest_utils.dart';
import '../types.dart';

class Ed25519KeyPair implements KeyPair {
  final String _keyId;
  final dynamic _privateKey;

  Ed25519KeyPair({required dynamic privateKey, required String keyId})
      : _privateKey = privateKey,
        _keyId = keyId;

  @override
  Future<String> getKeyId() async => _keyId;

  @override
  Future<Uint8List> getPublicKey() async =>
      Uint8List.fromList(ed.public(_privateKey).bytes);

  @override
  Future<KeyType> getKeyType() async => KeyType.ed25519;

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519sha256;
    if (signatureScheme != SignatureScheme.ed25519sha256) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only ed25519sha256 is supported with ed25519");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );

    return ed.sign(_privateKey, digest);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519sha256;
    if (signatureScheme != SignatureScheme.ed25519sha256) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only ed25519sha256 is supported with secp256k1");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );

    return ed.verify(ed.public(_privateKey), digest, signature);
  }

  Uint8List getSeed() => ed.seed(_privateKey);
}
