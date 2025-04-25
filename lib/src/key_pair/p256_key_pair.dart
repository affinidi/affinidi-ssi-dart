import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart' as ec;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import './_ecdh_utils.dart' as ecdh_utils;
import 'key_export.dart';
import 'key_pair.dart';
import 'public_key.dart';

/// A key pair implementation that uses the P-256 (secp256r1) elliptic curve
/// for cryptographic operations.
///
/// This key pair supports signing and verifying data using the
/// `ecdsa_p256_sha256` signature scheme. It also supports Elliptic Curve
/// Diffie-Hellman (ECDH) key agreement.
class P256KeyPair implements KeyPair, KeyExport {
  static final ec.EllipticCurve _p256 = ec.getP256();
  final ec.PrivateKey _privateKey;
  final String _id;
  Uint8List? _publicKeyBytes;

  P256KeyPair._(this._id, this._privateKey);

  /// Creates a new [P256KeyPair] instance with a randomly generated private key.
  factory P256KeyPair(String id) {
    return P256KeyPair._(id, _p256.generatePrivateKey());
  }

  /// Creates a [P256KeyPair] instance from a private key.
  ///
  /// [privateKey] - The private key as a [Uint8List].
  factory P256KeyPair.fromPrivateKey(String id, Uint8List privateKey) {
    return P256KeyPair._(id, ec.PrivateKey.fromBytes(_p256, privateKey));
  }

  @override
  PublicKey get publicKey {
    _publicKeyBytes ??= hex.decode(_privateKey.publicKey.toCompressedHex());
    return PublicKey(
      _id,
      _publicKeyBytes!,
      KeyType.p256,
    );
  }

  @override
  Future<Uint8List> get privateKey {
    return Future.value(Uint8List.fromList(_privateKey.bytes));
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
            "Unsupported signature scheme. Currently only ecdsa_p256_sha256 is supported with p256",
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
            "Unsupported signature scheme. Currently only ecdsa_p256_sha256 is supported with p256",
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
  encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = Uint8List.fromList(_privateKey.bytes);

    return ecdh_utils.encryptData(
      data: data,
      privateKeyBytes: privateKey,
      publicKeyBytes: publicKey,
      curve: _p256,
    );
  }

  @override
  decrypt(Uint8List ivAndBytes, {Uint8List? publicKey}) async {
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
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    final publicKeyObj = _p256.compressedHexToPublicKey(hex.encode(publicKey));
    final secret = computeSecret(_privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }

  @override
  String get id => _id;
}
