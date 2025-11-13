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

/// A key pair implementation that uses the P-256 (secp256r1) elliptic curve
/// for cryptographic operations.
///
/// This key pair supports signing and verifying data using the
/// `ecdsa_p256_sha256` signature scheme. It also supports Elliptic Curve
/// Diffie-Hellman (ECDH) key agreement.
class P256KeyPair extends KeyPair {
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

    // Rejection sampling to ensure private key is in [1, n-1]
    // Start with SHA-256(seed), and if invalid, retry with SHA-256(seed || counter).
    Uint8List candidate = digest.process(seed);
    final n = _p256.n; // Curve order

    int counter = 0;
    const int maxAttempts = 256;
    for (var attempts = 0; attempts < maxAttempts; attempts++) {
      // Interpret candidate as big-endian integer
      BigInt k = BigInt.zero;
      for (final b in candidate) {
        k = (k << 8) + BigInt.from(b);
      }

      if (k > BigInt.zero && k < n) {
        final effectiveId = id ?? randomId();
        return P256KeyPair._(
            ec.PrivateKey.fromBytes(_p256, candidate), effectiveId);
      }

      // Not in range; derive a new candidate deterministically
      counter = (counter + 1) & 0xff;
      final data = Uint8List(seed.length + 1)
        ..setRange(0, seed.length, seed)
        ..[seed.length] = counter;
      candidate = digest.process(data);
    }

    throw ArgumentError(
        'Failed to derive a valid P-256 private key from seed after $maxAttempts attempts');
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
  Future<Uint8List> internalSign(
      Uint8List data, SignatureScheme signatureScheme) async {
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    final digestSignature = ecdsa.signature(_privateKey, digest);
    return Uint8List.fromList(digestSignature.toCompact());
  }

  @override
  Future<bool> internalVerify(Uint8List data, Uint8List signature,
      SignatureScheme signatureScheme) async {
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    final signatureObj = ecdsa.Signature.fromCompact(signature);
    var result = ecdsa.verify(_privateKey.publicKey, digest, signatureObj);
    return Future.value(result);
  }

  @override
  SignatureScheme get defaultSignatureScheme =>
      SignatureScheme.ecdsa_p256_sha256;

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
