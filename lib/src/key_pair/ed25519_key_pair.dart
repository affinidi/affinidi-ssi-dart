import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'key_pair.dart';

/// A [KeyPair] implementation using the Ed25519 signature scheme.
///
/// This key pair supports signing and verifying data using Ed25519.
/// It does not support any other signature schemes.
class Ed25519KeyPair implements KeyPair {
  /// The key identifier.
  final String _keyId;

  /// The private key.
  final dynamic _privateKey;

  /// Constructs an [Ed25519KeyPair] from a [privateKey] and its associated [keyId].
  Ed25519KeyPair({
    required dynamic privateKey,
    required String keyId,
  })  : _privateKey = privateKey,
        _keyId = keyId;

  /// Returns the identifier of this key pair.
  @override
  Future<String> get id => Future.value(_keyId);

  /// Retrieves the public key.
  ///
  /// Returns the key as [Uint8List].
  @override
  Future<Uint8List> get publicKey => Future.value(
        Uint8List.fromList(
          ed.public(_privateKey).bytes,
        ),
      );

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.ed25519);

  /// Signs the provided data using Ed25519.
  ///
  /// [data] - The data to be signed.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature as a [Uint8List].
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed or
  /// if the signing operation fails.
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

  /// Verifies a signature using Ed25519.
  ///
  /// [data] - The data that was signed.
  /// [signature] - The signature to verify.
  /// [signatureScheme] - The signature scheme to use.
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
    signatureScheme ??= SignatureScheme.ed25519_sha256;
    if (signatureScheme != SignatureScheme.ed25519_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 is supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

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
    return ed.verify(ed.public(_privateKey), digest, signature);
  }

  /// Returns the original seed used to derive the Ed25519 key pair.
  Uint8List getSeed() => ed.seed(_privateKey);

  /// Returns the supported signature schemes for this key pair.
  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      const [SignatureScheme.ed25519_sha256];
}
