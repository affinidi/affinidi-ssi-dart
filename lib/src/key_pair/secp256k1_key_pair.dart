import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:bip32_plus/bip32_plus.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart' as ec;

import '../digest_utils.dart';
import '../types.dart';
import '../utility.dart';
import './_ecdh_utils.dart' as ecdh_utils;
import 'key_pair.dart';
import 'public_key.dart';

/// A key pair implementation that uses secp256k1 for crypto operations.
///
/// This key pair supports signing and verifying data using secp256k1.
/// It does not support any other signature schemes.
class Secp256k1KeyPair extends KeyPair {
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
  Future<Uint8List> internalSign(
      Uint8List data, SignatureScheme signatureScheme) async {
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.sign(digest);
  }

  @override
  Future<bool> internalVerify(Uint8List data, Uint8List signature,
      SignatureScheme signatureScheme) async {
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.verify(digest, signature);
  }

  @override
  SignatureScheme get defaultSignatureScheme =>
      SignatureScheme.ecdsa_secp256k1_sha256;

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

  /// Computes the Elliptic Curve Diffie-Hellman (ECDH) shared secret.
  ///
  /// [publicKey] - The public key of the other party (in compressed format).
  ///
  /// Returns the computed shared secret as a [Uint8List].
  @override
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    final publicKeyObj =
        _secp256k1.compressedHexToPublicKey(hex.encode(publicKey));
    final privateKey = ec.PrivateKey.fromBytes(_secp256k1, _node.privateKey!);
    final secret = computeSecret(privateKey, publicKeyObj);
    return Future.value(Uint8List.fromList(secret));
  }
}
