import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:x25519/x25519.dart' as x25519;
import 'package:cryptography/cryptography.dart' as crypto;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../utility.dart';
import '_ecdh_utils.dart';
import 'key_pair.dart';

import './_encryption_utils.dart';
import 'public_key.dart';

/// A [KeyPair] implementation using the Ed25519 signature scheme.
///
/// This key pair supports signing and verifying data using Ed25519.
/// It does not support any other signature schemes.
class Ed25519KeyPair implements KeyPair {
  final ed.PrivateKey _privateKey;
  final _encryptionUtils = EncryptionUtils();
  @override
  final String keyId;

  Ed25519KeyPair._(this._privateKey, this.keyId);

  /// Generates a new Ed25519 key pair.
  /// Returns the KeyPair instance and its private key bytes.
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  static (Ed25519KeyPair, Uint8List) generate({String? id}) {
    final keyPair = ed.generateKey();
    final effectiveId = id ?? randomId();
    final instance = Ed25519KeyPair._(keyPair.privateKey, effectiveId);
    final privateKeyBytes = Uint8List.fromList(keyPair.privateKey.bytes);
    return (instance, privateKeyBytes);
  }

  /// Creates a [Ed25519KeyPair] instance from a seed.
  ///
  /// [seed] - The seed as a 32 byte [Uint8List].
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  factory Ed25519KeyPair.fromSeed(Uint8List seed, {String? id}) {
    final privateKey = ed.newKeyFromSeed(seed);
    final effectiveId = id ?? randomId();
    return Ed25519KeyPair._(privateKey, effectiveId);
  }

  /// Creates a [Ed25519KeyPair] instance from a private key.
  ///
  /// [privateKeyBytes] - The private key as a [Uint8List].
  /// [id] - Optional identifier for the key pair. If not provided, a random ID is generated.
  factory Ed25519KeyPair.fromPrivateKey(Uint8List privateKeyBytes,
      {String? id}) {
    final effectiveId = id ?? randomId();
    return Ed25519KeyPair._(ed.PrivateKey(privateKeyBytes), effectiveId);
  }

  /// Retrieves the public key.
  ///
  /// Returns the key as [Uint8List].
  @override
  Future<PublicKey> get publicKey => Future.value(PublicKey(
        keyId,
        Uint8List.fromList(
          ed.public(_privateKey).bytes,
        ),
        KeyType.ed25519,
      ));

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
    signatureScheme ??= SignatureScheme.eddsa_sha512;
    if (signatureScheme != SignatureScheme.ed25519_sha256 &&
        signatureScheme != SignatureScheme.eddsa_sha512) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 and eddsa_sha512 are supported.',
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
    signatureScheme ??= SignatureScheme.eddsa_sha512;
    if (signatureScheme != SignatureScheme.ed25519_sha256 &&
        signatureScheme != SignatureScheme.eddsa_sha512) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 and eddsa_sha512 are supported.',
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
      const [SignatureScheme.ed25519_sha256, SignatureScheme.eddsa_sha512];

  List<int> generateEphemeralPubKey() {
    // Generate a completely new ephemeral X25519 key pair
    final eKeyPair = x25519.generateKeyPair();
    return eKeyPair.publicKey;
  }

  Future<Uint8List> computeEcdhSecret(List<int> publicKey) async {
    // Convert Ed25519 private key to X25519 private key
    // Ed25519 uses SHA-512 to derive the scalar and prefix from the seed
    // We need to use the same process to get the correct X25519 private key
    final seed = ed.seed(_privateKey);
    final secret = x25519.X25519(seed, publicKey);
    return Future.value(Uint8List.fromList(secret));
  }

  @override
  encrypt(Uint8List data, {Uint8List? publicKey}) async {
    List<int> publicKeyToUse;
    if (publicKey == null) {
      publicKeyToUse = generateEphemeralPubKey();
    } else {
      publicKeyToUse = publicKey;
    }

    final sharedSecret = await computeEcdhSecret(publicKeyToUse);

    final algorithm = crypto.Hkdf(
      hmac: crypto.Hmac.sha256(),
      outputLength: 32,
    );

    final secretKey = crypto.SecretKey(sharedSecret);

    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      nonce: staticHkdNonce,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    Uint8List symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final encryptedData = _encryptionUtils.encryptToBytes(symmetricKey, data);

    return Uint8List.fromList(publicKeyToUse + encryptedData);
  }

  @override
  decrypt(Uint8List ivAndBytes, {Uint8List? publicKey}) async {
    // Extract the ephemeral public key and the encrypted data
    final ephemeralPublicKeyBytes =
        ivAndBytes.sublist(0, compressedPublidKeyLength);
    final encryptedData = ivAndBytes
        .sublist(compressedPublidKeyLength); // The rest is the encrypted data

    Uint8List pubKeyToUse;
    if (publicKey == null) {
      pubKeyToUse = ephemeralPublicKeyBytes;
    } else {
      pubKeyToUse = publicKey;
    }

    final sharedSecret = await computeEcdhSecret(pubKeyToUse);

    final algorithm = crypto.Hkdf(
      hmac: crypto.Hmac.sha256(),
      outputLength: 32,
    );
    final secretKey = crypto.SecretKey(sharedSecret);
    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      nonce: staticHkdNonce,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    Uint8List symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final decryptedData =
        _encryptionUtils.decryptFromBytes(symmetricKey, encryptedData);

    if (decryptedData == null) {
      throw SsiException(
        message: 'Decryption failed, bytes are null',
        code: SsiExceptionType.unableToDecrypt.code,
      );
    }

    return decryptedData;
  }

  Future<crypto.SimplePublicKey> ed25519KeyToX25519PublicKey() async {
    // Convert Ed25519 private key to X25519 private key
    final seed = ed.seed(_privateKey);
    final algorithm = crypto.X25519();
    final keyPair = await algorithm.newKeyPairFromSeed(seed);
    return await keyPair.extractPublicKey();
  }
}
