import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:elliptic/elliptic.dart';

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'key_pair.dart';

import './_ecdh_utils.dart' as ecdh_utils;

/// A key pair implementation that uses secp256k1 for crypto operations.
///
/// This key pair supports signing and verifying data using secp256k1.
/// It does not support any other signature schemes.
class Secp256k1KeyPair implements KeyPair {
  /// The key identifier.
  final String _keyId;

  /// The BIP32 node containing the key material.
  final BIP32 _node;
  var _secp256k1;

  /// Creates a new [Secp256k1KeyPair] instance.
  ///
  /// [node] - The BIP32 node containing the key material.
  /// [keyId] - The key identifier.
  Secp256k1KeyPair({
    required BIP32 node,
    required String keyId,
  })  : _node = node,
        _keyId = keyId,
        _secp256k1 = getSecp256k1();

  @override
  Future<String> get id => Future.value(_keyId);

  /// Retrieves the public key.
  ///
  /// Returns the key as [Uint8List].
  @override
  Future<Uint8List> get publicKey => Future.value(_node.publicKey);

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.secp256k1);

  /// Signs the provided data using secp256k1.
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
    signatureScheme ??= SignatureScheme.ecdsa_secp256k1_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_secp256k1_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ecdsa_secp256k1_sha256 is supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.sign(digest);
  }

  /// Verifies a signature using secp256k1.
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
    signatureScheme ??= SignatureScheme.ecdsa_secp256k1_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_secp256k1_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ecdsa_secp256k1_sha256 is supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.verify(digest, signature);
  }

  /// Retrieves the underlying BIP32 node.
  ///
  /// Returns the [BIP32] node containing the key material.
  BIP32 getBip32Node() => _node;

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.ecdsa_secp256k1_sha256];

  @override
  encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = _node.privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    return ecdh_utils.encryptData(
      data: data,
      privateKeyBytes: privateKey,
      publicKeyBytes: publicKey,
      curve: _secp256k1,
    );
  }

  @override
  decrypt(Uint8List ivAndBytes, {Uint8List? publicKey}) async {
    final privateKey = _node.privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    return ecdh_utils.decryptData(
      encryptedPackage: ivAndBytes,
      privateKeyBytes: privateKey,
      publicKeyBytes: publicKey,
      curve: _secp256k1,
    );
  }
}
