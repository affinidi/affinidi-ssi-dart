import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'key_pair.dart';

import './_ecdh_utils.dart' as ecdh_utils;

/// A key pair implementation that uses the P-256 (secp256r1) elliptic curve
/// for cryptographic operations.
///
/// This key pair supports signing and verifying data using the
/// `ecdsa_p256_sha256` signature scheme. It also supports Elliptic Curve
/// Diffie-Hellman (ECDH) key agreement.
class P256KeyPair implements KeyPair {
  /// The P-256 curve instance.
  static final EllipticCurve _p256 = getP256();

  final PrivateKey _privateKey;
  Uint8List? _publicKeyBytes;

  P256KeyPair._({
    required PrivateKey privateKey,
  }) : _privateKey = privateKey;

  /// Creates a new [P256KeyPair] instance with a randomly generated private key.
  ///
  factory P256KeyPair.create() {
    return P256KeyPair._(
      privateKey: _p256.generatePrivateKey(),
    );
  }

  /// Creates a [P256KeyPair] instance from a private key hex string.
  ///
  /// [privateKeyHex] - The private key encoded as a hex string.
  factory P256KeyPair.fromPrivateKeyHex({
    required String privateKeyHex,
  }) {
    final privateKey = PrivateKey.fromHex(_p256, privateKeyHex);
    return P256KeyPair._(
      privateKey: privateKey,
    );
  }

  /// Returns the type of the public key.
  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.p256);

  /// Retrieves the public key in compressed format.
  ///
  /// Returns the key as [Uint8List].
  @override
  Future<Uint8List> get publicKey async {
    if (_publicKeyBytes == null) {
      final bytes = hex.decode(await publicKeyHex);
      _publicKeyBytes = Uint8List.fromList(bytes);
    }
    return Future.value(_publicKeyBytes!);
  }

  /// Retrieves the public key in compressed hex format.
  ///
  /// Returns the key as a [String].
  @override
  Future<String> get publicKeyHex {
    return Future.value(_privateKey.publicKey.toCompressedHex());
  }

  /// Retrieves the private key in hex format.
  ///
  /// Returns the key as a [String].
  @override
  Future<String> get privateKeyHex {
    return Future.value(_privateKey.toHex());
  }

  /// Signs the provided data using P-256 with SHA-256 hashing (ecdsa_p256_sha256).
  ///
  /// [data] - The data to be signed.
  /// [signatureScheme] - The signature scheme to use. If null, defaults to
  ///   `SignatureScheme.ecdsa_p256_sha256`.
  ///
  /// Returns a [Future] that completes with the signature in compact format
  /// as a [Uint8List].
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed.
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

  /// Verifies a signature using P-256 with SHA-256 hashing (ecdsa_p256_sha256).
  ///
  /// [data] - The data that was signed.
  /// [signature] - The signature (in compact format) to verify.
  /// [signatureScheme] - The signature scheme to use. If null, defaults to
  ///   `SignatureScheme.ecdsa_p256_sha256`.
  ///
  /// Returns a [Future] that completes with `true` if the signature is valid,
  /// `false` otherwise.
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed.
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

  /// Returns a list of [SignatureScheme]s supported by this key pair.
  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.ecdsa_p256_sha256];

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
}
