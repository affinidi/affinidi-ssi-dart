import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:x25519/x25519.dart' as x25519;
import 'package:cryptography/cryptography.dart' as crypto;

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'key_pair.dart';

import './_const.dart';
import './_encryption_utils.dart';

/// A [KeyPair] implementation using the Ed25519 signature scheme.
///
/// This key pair supports signing and verifying data using Ed25519.
/// It does not support any other signature schemes.
class Ed25519KeyPair implements KeyPair {
  /// The private key.
  final ed.PrivateKey _privateKey;
  final _encryptionUtils = EncryptionUtils();

  Ed25519KeyPair._(this._privateKey);

  factory Ed25519KeyPair() {
    final keyPair = ed.generateKey();
    return Ed25519KeyPair._(keyPair.privateKey);
  }

  factory Ed25519KeyPair.fromSeed(Uint8List seed) {
    final privateKey = ed.newKeyFromSeed(seed);
    return Ed25519KeyPair._(privateKey);
  }

  factory Ed25519KeyPair.fromPrivateKey(Uint8List privateKey) {
    return Ed25519KeyPair._(ed.PrivateKey(privateKey));
  }

  /// Returns the type of the public key.
  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.ed25519);

  /// Retrieves the public key.
  ///
  /// Returns the key as [Uint8List].
  @override
  Future<Uint8List> get publicKey => Future.value(
        Uint8List.fromList(
          ed.public(_privateKey).bytes,
        ),
      );

  /// Retrieves the public key hex encoded.
  ///
  /// Returns the key as [String].
  @override
  Future<String> get publicKeyHex async =>
      Future.value(hex.encode(await publicKey));

  /// Retrieves the private key in hex format.
  ///
  /// Returns the key as a [String].
  @override
  Future<String> get privateKeyHex {
    return Future.value(hex.encode(Uint8List.fromList(_privateKey.bytes)));
  }

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

  List<int> generateEphemeralPubKey() {
    var eKeyPair = x25519.generateKeyPair();
    var publicKey = eKeyPair.publicKey;

    return publicKey;
  }

  Future<Uint8List> computeEcdhSecret(List<int> publicKey) async {
    var privateKeyForX25519 =
        _privateKey.bytes.sublist(0, COMPRESSED_PUB_KEY_LENGTH);
    final secret = x25519.X25519(privateKeyForX25519, publicKey);
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
      nonce: STATIC_HKD_NONCE,
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
        ivAndBytes.sublist(0, COMPRESSED_PUB_KEY_LENGTH);
    final encryptedData = ivAndBytes
        .sublist(COMPRESSED_PUB_KEY_LENGTH); // The rest is the encrypted data

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
      nonce: STATIC_HKD_NONCE,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    Uint8List symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final decryptedData =
        _encryptionUtils.decryptFromBytes(symmetricKey, encryptedData);

    if (decryptedData == null) {
      throw UnimplementedError('Decryption failed, bytes are null');
    }

    return decryptedData;
  }

  Future<crypto.SimplePublicKey> ed25519KeyToX25519PublicKey() async {
    var privateKeyForX25519 =
        _privateKey.bytes.sublist(0, COMPRESSED_PUB_KEY_LENGTH);
    final algorithm = crypto.X25519();
    final keyPair = await algorithm.newKeyPairFromSeed(privateKeyForX25519);
    return await keyPair.extractPublicKey();
  }
}
