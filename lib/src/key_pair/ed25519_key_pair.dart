import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'key_pair.dart';

class Ed25519KeyPair implements KeyPair {
  final String _keyId;
  final dynamic _privateKey;

  Ed25519KeyPair({
    required dynamic privateKey,
    required String keyId,
  })  : _privateKey = privateKey,
        _keyId = keyId;

  @override
  Future<String> get id => Future.value(_keyId);

  @override
  Future<Uint8List> get publicKey => Future.value(
        Uint8List.fromList(
          ed.public(_privateKey).bytes,
        ),
      );

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.ed25519);

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519_sha256;
    if (signatureScheme != SignatureScheme.ed25519_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 is supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return ed.sign(_privateKey, digest);
  }

  @override
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519_sha256;

    if (signatureScheme != SignatureScheme.ed25519_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 is supported',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    if (signatureScheme != SignatureScheme.ed25519_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519sha256 is supported with ed25519.',
        code: SsiExceptionType.other.code,
      );
    }

    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return ed.verify(ed.public(_privateKey), digest, signature);
  }

  Uint8List getSeed() => ed.seed(_privateKey);

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      const [SignatureScheme.ed25519_sha256];
}
