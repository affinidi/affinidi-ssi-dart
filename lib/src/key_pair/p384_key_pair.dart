import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart' as ec;
import 'package:pointycastle/api.dart' as pc;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../utility.dart';
import './_ecdh_utils.dart' as ecdh_utils;
import './_key_pair_utils.dart';
import 'key_pair.dart';
import 'public_key.dart';

/// A key pair implementation that uses the P-384 elliptic curve
/// for cryptographic operations.
class P384KeyPair implements KeyPair {
  static final ec.EllipticCurve _p384 = ec.getP384();
  final ec.PrivateKey _privateKey;
  Uint8List? _publicKeyBytes;
  @override
  final String id;

  P384KeyPair._(this._privateKey, this.id);

  /// Generates a new P384 key pair.
  static (P384KeyPair, Uint8List) generate({String? id}) {
    final privateKey = generateValidPrivateKey(_p384.generatePrivateKey);
    final effectiveId = id ?? randomId();
    final instance = P384KeyPair._(privateKey, effectiveId);
    final privateKeyBytes = Uint8List.fromList(privateKey.bytes);
    return (instance, privateKeyBytes);
  }

  /// Creates a [P384KeyPair] instance from a seed.
  factory P384KeyPair.fromSeed(Uint8List seed, {String? id}) {
    final digest = pc.Digest('SHA-384');
    final privateKeyBytes = digest.process(seed);
    final effectiveId = id ?? randomId();
    return P384KeyPair._(
        ec.PrivateKey.fromBytes(_p384, privateKeyBytes), effectiveId);
  }

  /// Creates a [P384KeyPair] instance from a private key.
  factory P384KeyPair.fromPrivateKey(Uint8List privateKeyBytes, {String? id}) {
    final effectiveId = id ?? randomId();
    return P384KeyPair._(
        ec.PrivateKey.fromBytes(_p384, privateKeyBytes), effectiveId);
  }

  @override
  PublicKey get publicKey {
    _publicKeyBytes ??= hex.decode(_privateKey.publicKey.toCompressedHex());
    return PublicKey(id, _publicKeyBytes!, KeyType.p384);
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_p384_sha384;
    if (signatureScheme != SignatureScheme.ecdsa_p384_sha384) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Currently only ecdsa_p384_sha384 is supported with p384',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
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
    signatureScheme ??= SignatureScheme.ecdsa_p384_sha384;
    if (signatureScheme != SignatureScheme.ecdsa_p384_sha384) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Currently only ecdsa_p384_sha384 is supported with p384',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
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
  List<SignatureScheme> get supportedSignatureSchemes => [];

  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = Uint8List.fromList(_privateKey.bytes);
    return ecdh_utils.encryptData(
      data: data,
      privateKeyBytes: privateKey,
      publicKeyBytes: publicKey,
      curve: _p384,
    );
  }

  @override
  Future<Uint8List> decrypt(Uint8List ivAndBytes,
      {Uint8List? publicKey}) async {
    final privateKey = Uint8List.fromList(_privateKey.bytes);
    return ecdh_utils.decryptData(
      encryptedPackage: ivAndBytes,
      privateKeyBytes: privateKey,
      publicKeyBytes: publicKey,
      curve: _p384,
    );
  }

  @override
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    final publicKeyObj = _p384.compressedHexToPublicKey(hex.encode(publicKey));
    final secret = computeSecret(_privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }
}
