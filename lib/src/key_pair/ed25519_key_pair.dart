import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:affinidi_tdk_cryptography/affinidi_tdk_cryptography.dart';

import '../digest_utils.dart';
import '../types.dart';
import 'key_pair.dart';

class Ed25519KeyPair implements KeyPair {
  final String _keyId;
  final dynamic _privateKey;
  final CryptographyService _cryptographyService;

  Ed25519KeyPair({
    required dynamic privateKey,
    required String keyId,
  })  : _privateKey = privateKey,
        _keyId = keyId,
        _cryptographyService = CryptographyService();

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
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519_sha256;
    if (signatureScheme != SignatureScheme.ed25519_sha256) {
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

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      const [SignatureScheme.ed25519_sha256];

  @override
  Future<Uint8List> encrypt(Uint8List data, { Uint8List? publicKey }) async {
    return _cryptographyService.encryptToBytes(_privateKey, data);
  }

  @override
  Future<Uint8List> decrypt(Uint8List ivAndBytes, { Uint8List? publicKey }) async {
    final decryptedBytes = await _cryptographyService.decryptFromBytes(_privateKey, ivAndBytes);
    if (decryptedBytes == null) {
      throw UnimplementedError('Decryption failed, bytes are null');
    }
    return decryptedBytes;
  }
}
