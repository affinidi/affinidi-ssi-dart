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

/// A key pair implementation that uses the P-521 elliptic curve
/// for cryptographic operations.
class P521KeyPair implements KeyPair {
  static final ec.Curve _p521 = ec.getP521();
  static final expectedLength = 66;
  static final maxAttempts = 10;
  final ec.PrivateKey _privateKey;
  Uint8List? _publicKeyBytes;
  @override
  final String id;

  P521KeyPair._(this._privateKey, this.id);

  /// Generates a new P521 key pair.
  static (P521KeyPair, Uint8List) generate({String? id}) {
    final privateKeyEcdsa = ecdsa.;
    final privateKey = generateValidPrivateKey(_p521.generatePrivateKey,
        maxAttempts: maxAttempts, expectedLength: expectedLength);
    final effectiveId = id ?? randomId();
    final instance = P521KeyPair._(privateKey, effectiveId);
    final privateKeyBytes = Uint8List.fromList(privateKey.bytes);
    return (instance, privateKeyBytes);
  }

  /// Creates a [P521KeyPair] instance from a seed.
  factory P521KeyPair.fromSeed(Uint8List seed, {String? id}) {
    final digest = pc.Digest('SHA-512');
    final privateKeyBytes = digest.process(seed);
    final effectiveId = id ?? randomId();
    return P521KeyPair._(
        ec.PrivateKey.fromBytes(_p521, privateKeyBytes), effectiveId);
  }

  /// Creates a [P521KeyPair] instance from a private key.
  factory P521KeyPair.fromPrivateKey(Uint8List privateKeyBytes, {String? id}) {
    final effectiveId = id ?? randomId();
    return P521KeyPair._(
        ec.PrivateKey.fromBytes(_p521, privateKeyBytes), effectiveId);
  }

  @override
  PublicKey get publicKey {
    _publicKeyBytes ??= hex.decode(_privateKey.publicKey.toCompressedHex());
    return PublicKey(id, _publicKeyBytes!, KeyType.p521);
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_p521_sha512;
    if (signatureScheme != SignatureScheme.ecdsa_p521_sha512) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Currently only ecdsa_p521_sha512 is supported with p521',
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
    signatureScheme ??= SignatureScheme.ecdsa_p521_sha512;
    if (signatureScheme != SignatureScheme.ecdsa_p521_sha512) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Currently only ecdsa_p521_sha512 is supported with p521',
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
      curve: _p521,
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
      curve: _p521,
    );
  }

  @override
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    final publicKeyObj = _p521.compressedHexToPublicKey(hex.encode(publicKey));
    final secret = computeSecret(_privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }
}
