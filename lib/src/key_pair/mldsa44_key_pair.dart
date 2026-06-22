import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pqcrypto/pqcrypto.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../utility.dart';
import 'key_pair.dart';
import 'public_key.dart';

/// ML-DSA-44 key-pair sizes (FIPS 204 Table 2, parameter set ML-DSA-44).
const int _mlDsa44PublicKeyBytes = 1312;
const int _mlDsa44SecretKeyBytes = 2560;
const int _mlDsa44SignatureBytes = 2420;

/// Combined blob size stored as `privateKeyBytes` in the wallet: sk (2560) || pk (1312).
const int _mlDsa44KeyBlobBytes =
    _mlDsa44SecretKeyBytes + _mlDsa44PublicKeyBytes;

/// HKDF derivation constants — **frozen forever** (changing them changes derived keys).
const String _hkdfSalt = 'ssi-mldsa44';
const String _hkdfInfo = 'ML-DSA-44 keygen v1';

/// A [KeyPair] implementation for the ML-DSA-44 post-quantum signature scheme
/// (FIPS 204, CRYSTALS-Dilithium).
///
/// **Sign/verify only.** ML-DSA-44 is a signature algorithm and does not
/// support encryption or key agreement. Calling [encrypt], [decrypt], or
/// [computeEcdhSecret] will throw an [SsiException].
///
/// **Persistence format:** [generate] returns a 3872-byte blob as
/// `privateKeyBytes` containing the secret key (first 2560 bytes) followed by
/// the public key (last 1312 bytes).  Pass the same blob to [fromPrivateKey]
/// to reconstruct the key pair.
///
/// ## Security note on deterministic derivation
///
/// [fromSeed] derives a stable ML-DSA-44 keypair from existing key material
/// via HKDF-SHA256. A PQ key derived from a potentially quantum-vulnerable
/// classical seed does **not** retroactively protect the classical key; it
/// only provides reproducible PQ key management.
class MlDsa44KeyPair extends KeyPair {
  static final _params = DilithiumParams.mlDsa44;

  final Uint8List _secretKey;
  final Uint8List _publicKey;

  @override
  final String id;

  MlDsa44KeyPair._(this._secretKey, this._publicKey, this.id);

  /// Generates a fresh ML-DSA-44 key pair using a cryptographically secure
  /// random source.
  ///
  /// Returns a tuple of the [MlDsa44KeyPair] instance and a 3872-byte blob
  /// `[sk || pk]` which is what gets persisted as `privateKeyBytes` in the
  /// wallet store.  Use [fromPrivateKey] to reconstruct from this blob.
  ///
  /// [id] — optional wallet-internal key identifier; a random ID is generated
  /// if not provided.
  static (MlDsa44KeyPair, Uint8List) generate({String? id}) {
    final effectiveId = id ?? randomId();
    final (pk, sk) = MlDsa.generateKeyPair(_params);
    final keyBlob = Uint8List(_mlDsa44KeyBlobBytes)
      ..setRange(0, _mlDsa44SecretKeyBytes, sk)
      ..setRange(_mlDsa44SecretKeyBytes, _mlDsa44KeyBlobBytes, pk);
    return (
      MlDsa44KeyPair._(
          Uint8List.fromList(sk), Uint8List.fromList(pk), effectiveId),
      keyBlob
    );
  }

  /// Restores an [MlDsa44KeyPair] from a persisted key blob.
  ///
  /// [keyBlob] must be the 3872-byte `[sk || pk]` blob produced by [generate]
  /// or [fromSeed] (via their `privateKeyBytes` return value / helper).
  factory MlDsa44KeyPair.fromPrivateKey(
    Uint8List keyBlob, {
    String? id,
  }) {
    if (keyBlob.length != _mlDsa44KeyBlobBytes) {
      throw SsiException(
        message:
            'Invalid ML-DSA-44 key blob length: expected $_mlDsa44KeyBlobBytes bytes (sk||pk), got ${keyBlob.length}',
        code: SsiExceptionType.keyPairMissingPrivateKey.code,
      );
    }
    final effectiveId = id ?? randomId();
    final sk = keyBlob.sublist(0, _mlDsa44SecretKeyBytes);
    final pk = keyBlob.sublist(_mlDsa44SecretKeyBytes);
    return MlDsa44KeyPair._(
        Uint8List.fromList(sk), Uint8List.fromList(pk), effectiveId);
  }

  /// Derives a deterministic ML-DSA-44 keypair from arbitrary input key
  /// material using HKDF-SHA256.
  ///
  /// KDF: `xi = HKDF-SHA256(ikm=seed, salt="ssi-mldsa44",
  ///                         info="ML-DSA-44 keygen v1", L=32)`
  ///
  /// The salt and info strings are **frozen**: changing them would produce
  /// different keys from the same seed.
  ///
  /// Returns a tuple of `(MlDsa44KeyPair, Uint8List keyBlob)` where `keyBlob`
  /// is the 3872-byte `[sk || pk]` blob suitable for wallet persistence.
  ///
  /// **Security note:** Deriving a PQ key from a potentially quantum-vulnerable
  /// classical seed does not retroactively protect the classical key; it only
  /// provides reproducible PQ key management.
  static Future<(MlDsa44KeyPair, Uint8List)> fromSeed(
    Uint8List seed, {
    String? id,
  }) async {
    final effectiveId = id ?? randomId();
    final xi = await _deriveXi(seed);
    final (pk, sk) = MlDsa.generateKeyPairSeeded(_params, xi);
    final keyBlob = Uint8List(_mlDsa44KeyBlobBytes)
      ..setRange(0, _mlDsa44SecretKeyBytes, sk)
      ..setRange(_mlDsa44SecretKeyBytes, _mlDsa44KeyBlobBytes, pk);
    return (
      MlDsa44KeyPair._(
          Uint8List.fromList(sk), Uint8List.fromList(pk), effectiveId),
      keyBlob
    );
  }

  /// Derives the 32-byte ML-DSA-44 seed (xi) from arbitrary input key material
  /// via HKDF-SHA256.
  static Future<Uint8List> _deriveXi(Uint8List ikm) async {
    final algorithm = crypto.Hkdf(
      hmac: crypto.Hmac.sha256(),
      outputLength: 32,
    );
    final derivedKey = await algorithm.deriveKey(
      secretKey: crypto.SecretKey(ikm),
      nonce: _hkdfSalt.codeUnits,
      info: _hkdfInfo.codeUnits,
    );
    return Uint8List.fromList(await derivedKey.extractBytes());
  }

  @override
  PublicKey get publicKey => PublicKey(id, _publicKey, KeyType.mldsa44);

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.mldsa44];

  @override
  SignatureScheme get defaultSignatureScheme => SignatureScheme.mldsa44;

  @override
  Future<Uint8List> internalSign(
    Uint8List data,
    SignatureScheme signatureScheme,
  ) async {
    // Use hedged external ML-DSA signing (rnd drawn from Random.secure).
    // Do NOT pre-hash: ML-DSA signs the raw hashData bytes directly.
    final sig = MlDsa.sign(_secretKey, data, _params);
    return sig;
  }

  @override
  Future<bool> internalVerify(
    Uint8List data,
    Uint8List signature,
    SignatureScheme signatureScheme,
  ) async {
    if (signature.length != _mlDsa44SignatureBytes) {
      return false;
    }
    return MlDsa.verify(_publicKey, data, signature, _params);
  }

  /// Not supported — ML-DSA-44 is a signature-only algorithm.
  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) {
    throw SsiException(
      message:
          'ML-DSA-44 is a signature-only algorithm and does not support encryption.',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }

  /// Not supported — ML-DSA-44 is a signature-only algorithm.
  @override
  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey}) {
    throw SsiException(
      message:
          'ML-DSA-44 is a signature-only algorithm and does not support decryption.',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }

  /// Not supported — ML-DSA-44 is a signature-only algorithm.
  @override
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) {
    throw SsiException(
      message:
          'ML-DSA-44 is a signature-only algorithm and does not support key agreement.',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }
}
