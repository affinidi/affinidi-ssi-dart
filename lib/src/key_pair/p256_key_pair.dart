import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';

import '../digest_utils.dart';
import '../types.dart';
import 'key_pair.dart';

class P256KeyPair implements KeyPair {
  final EllipticCurve _p256;
  final PrivateKey _privateKey;
  final String _keyId;

  P256KeyPair._({
    required EllipticCurve p256,
    required PrivateKey privateKey,
    required String keyId,
  })  : _p256 = p256,
        _privateKey = privateKey,
        _keyId = keyId;

  factory P256KeyPair.create({
    required String keyId,
  }) {
    final p256 = getP256();
    return P256KeyPair._(
      p256: p256,
      privateKey: p256.generatePrivateKey(),
      keyId: keyId,
    );
  }

  @override
  Future<String> get id => Future.value(_keyId);

  @override
  Future<Uint8List> get publicKey async {
    final bytes = hex.decode(await publicKeyHex);
    return Future.value(Uint8List.fromList(bytes));
  }

  Future<String> get publicKeyHex {
    return Future.value(_privateKey.publicKey.toCompressedHex());
  }

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.p256);

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_p256_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_p256_sha256) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only ecdsa_p256_sha256 is supported with p256");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    final digestSignature = ecdsa.signature(_privateKey, digest);
    return Uint8List.fromList(digestSignature.toCompact());
  }

  @override
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_p256_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_p256_sha256) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only ecdsa_p256_sha256 is supported with p256");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    final signatureObj = ecdsa.Signature.fromCompact(signature);
    var result = ecdsa.verify(_privateKey.publicKey, digest, signatureObj);
    return Future.value(result);
  }

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.ecdsa_p256_sha256];

  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    final publicKeyObj = _p256.compressedHexToPublicKey(hex.encode(publicKey));
    final secret = computeSecret(_privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }

  Future<Uint8List> computeEcdhSecretFromHex(String publicKeyHex) async {
    final publicKeyObj = _p256.compressedHexToPublicKey(publicKeyHex);
    final secret = computeSecret(_privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }
}
