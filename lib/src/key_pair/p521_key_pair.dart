import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart' as ec;
import 'package:pointycastle/api.dart' as pc;

import '../digest_utils.dart';
import '../types.dart';
import '../utility.dart';
import './_ecdh_utils.dart' as ecdh_utils;
import 'key_pair.dart';
import 'public_key.dart';

/// A key pair implementation that uses the P-521 elliptic curve
/// for cryptographic operations.
class P521KeyPair extends KeyPair {
  static final ec.Curve _p521 = ec.getP521();
  final ec.PrivateKey _privateKey;
  Uint8List? _publicKeyBytes;
  @override
  final String id;

  P521KeyPair._(this._privateKey, this.id);

  /// Generates a new P521 key pair.
  static (P521KeyPair, Uint8List) generate({String? id}) {
    final privateKey = _p521.generatePrivateKey();
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
    if (privateKeyBytes.length != 66) {
      throw ArgumentError(
          'P-521 private key must be 66 bytes, got \\${privateKeyBytes.length}');
    }
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
  Future<Uint8List> internalSign(
      Uint8List data, SignatureScheme signatureScheme) async {
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    final digestSignature = ecdsa.signature(_privateKey, digest);
    return Uint8List.fromList(_toCompact521(digestSignature));
  }

  @override
  Future<bool> internalVerify(Uint8List data, Uint8List signature,
      SignatureScheme signatureScheme) async {
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    final signatureObj = _fromCompact521(signature);
    var result = ecdsa.verify(_privateKey.publicKey, digest, signatureObj);
    return Future.value(result);
  }

  @override
  List<SignatureScheme> get supportedSignatureSchemes => [];

  @override
  SignatureScheme get defaultSignatureScheme =>
      SignatureScheme.ecdsa_p521_sha512;

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

  List<int> _toCompact521(ecdsa.Signature signature) {
    final rHex = signature.R
        .toRadixString(16)
        .padLeft(132, '0'); // 66 bytes = 132 hex chars
    final sHex = signature.S
        .toRadixString(16)
        .padLeft(132, '0'); // 66 bytes = 132 hex chars

    final result = <int>[];
    for (int i = 0; i < rHex.length; i += 2) {
      result.add(int.parse(rHex.substring(i, i + 2), radix: 16));
    }
    for (int i = 0; i < sHex.length; i += 2) {
      result.add(int.parse(sHex.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  /// Custom compact deserialization for P-521 signatures
  /// P-521 requires 66 bytes for r and 66 bytes for s (total 132 bytes)
  ecdsa.Signature _fromCompact521(Uint8List compactBytes) {
    if (compactBytes.length != 132) {
      throw ArgumentError(
          'P-521 compact signature must be 132 bytes, got ${compactBytes.length}');
    }

    // Extract r (first 66 bytes)
    final rBytes = compactBytes.sublist(0, 66);
    final rHex = rBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final r = BigInt.parse(rHex, radix: 16);

    // Extract s (last 66 bytes)
    final sBytes = compactBytes.sublist(66, 132);
    final sHex = sBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final s = BigInt.parse(sHex, radix: 16);

    return ecdsa.Signature.fromRS(r, s);
  }
}
