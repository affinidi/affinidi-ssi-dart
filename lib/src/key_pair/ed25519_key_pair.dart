import 'dart:typed_data';

import 'package:crypto/crypto.dart' as dart_crypto;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:pinenacl/tweetnacl.dart';
import 'package:pinenacl/x25519.dart' as x25519;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../utility.dart';
import './_encryption_utils.dart';
import '_ecdh_utils.dart';
import 'ed25519_verifier.dart';
import 'key_pair.dart';
import 'public_key.dart';

/// A [KeyPair] implementation using the Ed25519 signature scheme.
///
/// This key pair supports signing and verifying data using Ed25519.
/// It does not support any other signature schemes.
class Ed25519KeyPair extends KeyPair {
  final ed.SigningKey _privateKey;
  final _encryptionUtils = EncryptionUtils();
  @override
  final String id;

  Ed25519KeyPair._(this._privateKey, this.id);

  /// Generates a new Ed25519 key pair.
  /// Returns the KeyPair instance and its private key bytes.
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  static (Ed25519KeyPair, Uint8List) generate({String? id}) {
    final privateKey = ed.SigningKey.generate();
    final effectiveId = id ?? randomId();
    final instance = Ed25519KeyPair._(privateKey, effectiveId);
    final privateKeyBytes = Uint8List.fromList([
      ...privateKey.seed,
      ...privateKey.verifyKey,
    ]);
    return (instance, privateKeyBytes);
  }

  /// Creates a [Ed25519KeyPair] instance from a seed.
  ///
  /// [seed] - The seed as a 32 byte [Uint8List].
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  factory Ed25519KeyPair.fromSeed(Uint8List seed, {String? id}) {
    final privateKey = ed.SigningKey.fromSeed(seed);
    final effectiveId = id ?? randomId();
    return Ed25519KeyPair._(privateKey, effectiveId);
  }

  /// Creates a [Ed25519KeyPair] instance from a private key.
  ///
  /// [privateKeyBytes] - The private key as a [Uint8List].
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  factory Ed25519KeyPair.fromPrivateKey(
    Uint8List privateKeyBytes, {
    String? id,
  }) {
    final effectiveId = id ?? randomId();
    return Ed25519KeyPair._(
      ed.SigningKey.fromSeed(privateKeyBytes.sublist(0, 32)),
      effectiveId,
    );
  }

  /// Retrieves the public key.
  ///
  /// Returns the key as [Uint8List].
  @override
  PublicKey get publicKey => PublicKey(
        id,
        Uint8List.fromList(_privateKey.verifyKey),
        KeyType.ed25519,
      );

  @override
  Future<Uint8List> internalSign(
      Uint8List data, SignatureScheme signatureScheme) async {
    // For Ed25519, the library handles hashing internally
    return Uint8List.fromList(_privateKey.sign(data).signature);
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
  Future<bool> internalVerify(Uint8List data, Uint8List signature,
      SignatureScheme signatureScheme) async {
    return verifyEd25519Signature(
      Uint8List.fromList(_privateKey.verifyKey),
      data,
      signature,
    );
  }

  /// Returns the original seed used to derive the Ed25519 key pair.
  Uint8List getSeed() => Uint8List.fromList(_privateKey.seed);

  @override
  SignatureScheme get defaultSignatureScheme => SignatureScheme.ed25519;

  /// Generates a new ephemeral X25519 public key.
  List<int> generateEphemeralPubKey() {
    // Generate a completely new ephemeral X25519 key pair
    final privateKey = x25519.PrivateKey.generate();
    return Uint8List.fromList(privateKey.publicKey);
  }

  /// Computes the ECDH shared secret using the provided public key.
  ///
  /// [publicKey] - The public key to use for computing the shared secret.
  ///
  /// Returns a [Future] that completes with the shared secret as a [Uint8List].
  @override
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey) async {
    // Convert Ed25519 private key to X25519 private key
    // Ed25519 uses SHA-512 to derive the scalar and prefix from the seed
    // We need to use the same process to get the correct X25519 private key
    final seed = _privateKey.seed;
    // Hash the seed with SHA-512
    final hash = dart_crypto.sha512.convert(seed).bytes;
    // Clamp the first 32 bytes
    final clamped = Uint8List.fromList(hash.sublist(0, 32));
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    // Use the clamped value as the X25519 private key
    final secret = TweetNaCl.crypto_scalarmult(
      Uint8List(32),
      clamped,
      publicKey,
    );
    return Future.value(Uint8List.fromList(secret));
  }

  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) async {
    Uint8List publicKeyToUse;
    if (publicKey == null) {
      publicKeyToUse = Uint8List.fromList(generateEphemeralPubKey());
    } else {
      publicKeyToUse = publicKey;
    }

    final sharedSecret = await computeEcdhSecret(
      Uint8List.fromList(publicKeyToUse),
    );

    final algorithm = crypto.Hkdf(hmac: crypto.Hmac.sha256(), outputLength: 32);

    final secretKey = crypto.SecretKey(sharedSecret);

    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      nonce: staticHkdNonce,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    var symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final encryptedData = _encryptionUtils.encryptToBytes(symmetricKey, data);

    return Uint8List.fromList(publicKeyToUse + encryptedData);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List ivAndBytes, {
    Uint8List? publicKey,
  }) async {
    // Extract the ephemeral public key and the encrypted data
    final ephemeralPublicKeyBytes = ivAndBytes.sublist(
      0,
      compressedPublicKeyLength,
    );
    final encryptedData = ivAndBytes.sublist(
      compressedPublicKeyLength,
    ); // The rest is the encrypted data

    Uint8List pubKeyToUse;
    if (publicKey == null) {
      pubKeyToUse = ephemeralPublicKeyBytes;
    } else {
      pubKeyToUse = publicKey;
    }

    final sharedSecret = await computeEcdhSecret(pubKeyToUse);

    final algorithm = crypto.Hkdf(hmac: crypto.Hmac.sha256(), outputLength: 32);
    final secretKey = crypto.SecretKey(sharedSecret);
    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      nonce: staticHkdNonce,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    var symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final decryptedData = _encryptionUtils.decryptFromBytes(
      symmetricKey,
      encryptedData,
    );

    if (decryptedData == null) {
      throw SsiException(
        message: 'Decryption failed, bytes are null',
        code: SsiExceptionType.unableToDecrypt.code,
      );
    }

    return decryptedData;
  }

  /// Converts the Ed25519 key to an X25519 public key.
  /// Returns a [Future] that completes with the X25519 [PublicKey].
  Future<PublicKey> ed25519KeyToX25519PublicKey() async {
    final x25519PublicKeyBytes =
        ed25519PublicToX25519Public(_privateKey.verifyKey);
    return PublicKey(id, x25519PublicKeyBytes, KeyType.x25519);
  }
}
