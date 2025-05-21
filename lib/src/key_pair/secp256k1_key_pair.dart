import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:bip32_plus/bip32_plus.dart';
import 'package:elliptic/elliptic.dart' as ec;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../utility.dart';
import './_ecdh_utils.dart' as ecdh_utils;
import 'key_pair.dart';
import 'public_key.dart';

/// A key pair implementation that uses secp256k1 for crypto operations.
///
/// This key pair supports signing and verifying data using secp256k1.
/// It does not support any other signature schemes.
class Secp256k1KeyPair implements KeyPair {
  /// The BIP32 node containing the key material.
  final BIP32 _node;
  final ec.Curve _secp256k1 = ec.getSecp256k1();
  @override
  final String id;

  /// Creates a new [Secp256k1KeyPair] instance.
  ///
  /// [node] - The BIP32 node containing the key material.
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  Secp256k1KeyPair({
    required BIP32 node,
    String? id,
  })  : _node = node,
        id = id ?? randomId();

  @override
  PublicKey get publicKey => PublicKey(id, _node.publicKey, KeyType.secp256k1);

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

    final singature = _node.sign(digest);
    final r = singature.sublist(0, 32);
    final s = singature.sublist(32, 64);
    // Enforce low S value for signature malleability prevention
    final halfN = _secp256k1.n >> 1;
    final sBigInt = BigInt.parse(hex.encode(s), radix: 16);
    
    if (sBigInt > halfN) {
      // If s > N/2, set s = N - s to get the lower value
      final newS = _secp256k1.n - sBigInt;
      final newSBytes = hex.decode(newS.toRadixString(16).padLeft(64, '0'));
      return Uint8List.fromList(List.from(r)..addAll(newSBytes));
    }

    return singature;
  }

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

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.ecdsa_secp256k1_sha256];

  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) async {
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
  Future<Uint8List> decrypt(
    Uint8List ivAndBytes, {
    Uint8List? publicKey,
  }) async {
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
