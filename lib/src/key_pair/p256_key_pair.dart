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

/// A key pair implementation that uses the P-256 (secp256r1) elliptic curve
/// for cryptographic operations.
///
/// This key pair supports signing and verifying data using the
/// `ecdsa_p256_sha256` signature scheme. It also supports Elliptic Curve
/// Diffie-Hellman (ECDH) key agreement.
class P256KeyPair implements KeyPair {
  static final ec.EllipticCurve _p256 = ec.getP256();
  final ec.PrivateKey _privateKey;
  Uint8List? _publicKeyBytes;
  @override
  final String id;

  P256KeyPair._(this._privateKey, this.id);

  /// Generates a new P256 key pair.
  /// Returns the KeyPair instance and its private key bytes.
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  static (P256KeyPair, Uint8List) generate({String? id}) {
    final privateKey = _p256.generatePrivateKey();
    final effectiveId = id ?? randomId();
    final instance = P256KeyPair._(privateKey, effectiveId);
    final privateKeyBytes = Uint8List.fromList(privateKey.bytes);
    return (instance, privateKeyBytes);
  }

  /// Creates a [P256KeyPair] instance from a seed.
  ///
  /// [seed] - The seed as a [Uint8List].
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  factory P256KeyPair.fromSeed(Uint8List seed, {String? id}) {
    final digest = pc.Digest('SHA-256');
    final privateKeyBytes = digest.process(seed);
    final effectiveId = id ?? randomId();
    return P256KeyPair._(
        ec.PrivateKey.fromBytes(_p256, privateKeyBytes), effectiveId);
  }

  /// Creates a [P256KeyPair] instance from a private key.
  ///
  /// [privateKeyBytes] - The private key as a [Uint8List].
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  factory P256KeyPair.fromPrivateKey(Uint8List privateKeyBytes, {String? id}) {
    final effectiveId = id ?? randomId();
    return P256KeyPair._(
        ec.PrivateKey.fromBytes(_p256, privateKeyBytes), effectiveId);
  }

  @override
  PublicKey get publicKey {
    _publicKeyBytes ??= hex.decode(_privateKey.publicKey.toCompressedHex());
    return PublicKey(id, _publicKeyBytes!, KeyType.p256);
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_p256_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_p256_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Currently only ecdsa_p256_sha256 is supported with p256',
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
    signatureScheme ??= SignatureScheme.ecdsa_p256_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_p256_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Currently only ecdsa_p256_sha256 is supported with p256',
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
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.ecdsa_p256_sha256];

  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = Uint8List.fromList(_privateKey.bytes);

    return ecdh_utils.encryptData(
      data: data,
      privateKeyBytes: privateKey,
      publicKeyBytes: publicKey,
      curve: _p256,
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
      curve: _p256,
    );
  }

  /// Computes the Elliptic Curve Diffie-Hellman (ECDH) shared secret.
  ///
  /// [publicKey] - The public key of the other party (in compressed format).
  ///
  /// Returns the computed shared secret as a [Uint8List].
  @override
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    final publicKeyObj = _p256.compressedHexToPublicKey(hex.encode(publicKey));
    final secret = computeSecret(_privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }
}
