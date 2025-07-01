import 'dart:typed_data';

import 'package:crypto/crypto.dart' as dart_crypto;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:x25519/x25519.dart' as x25519;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../utility.dart';
import './_encryption_utils.dart';
import '_ecdh_utils.dart';
import 'key_pair.dart';
import 'public_key.dart';

/// A [KeyPair] implementation using the Ed25519 signature scheme.
///
/// This key pair supports signing and verifying data using Ed25519.
/// It does not support any other signature schemes.
class Ed25519KeyPair implements KeyPair {
  final ed.PrivateKey _privateKey;
  final _encryptionUtils = EncryptionUtils();
  @override
  final String id;

  Ed25519KeyPair._(this._privateKey, this.id);

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
  PublicKey get publicKey => PublicKey(
        id,
        Uint8List.fromList(
          ed.public(_privateKey).bytes,
        ),
        KeyType.ed25519,
      );

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
    signatureScheme ??= SignatureScheme.ed25519;
    if (signatureScheme != SignatureScheme.ed25519) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 and eddsa_sha512 are supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    // For Ed25519, the library handles hashing internally
    return ed.sign(_privateKey, data);
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
    signatureScheme ??= SignatureScheme.ed25519;
    if (signatureScheme != SignatureScheme.ed25519) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 and eddsa_sha512 are supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    // For Ed25519, the library handles hashing internally
    return ed.verify(ed.public(_privateKey), data, signature);
  }

  /// Returns the original seed used to derive the Ed25519 key pair.
  Uint8List getSeed() => ed.seed(_privateKey);

  /// Returns the supported signature schemes for this key pair.
  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      const [SignatureScheme.ed25519];

  @override
  SignatureScheme get defaultSignatureScheme => SignatureScheme.ed25519;

  /// Generates a new ephemeral X25519 public key.
  List<int> generateEphemeralPubKey() {
    // Generate a completely new ephemeral X25519 key pair
    final eKeyPair = x25519.generateKeyPair();
    return eKeyPair.publicKey;
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
    final seed = ed.seed(_privateKey);
    // Hash the seed with SHA-512
    final hash = dart_crypto.sha512.convert(seed).bytes;
    // Clamp the first 32 bytes
    final clamped = Uint8List.fromList(hash.sublist(0, 32));
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    // Use the clamped value as the X25519 private key
    final secret = x25519.X25519(clamped, publicKey);
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

    final sharedSecret =
        await computeEcdhSecret(Uint8List.fromList(publicKeyToUse));

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

    var symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final encryptedData = _encryptionUtils.encryptToBytes(symmetricKey, data);

    return Uint8List.fromList(publicKeyToUse + encryptedData);
  }

  @override
  Future<Uint8List> decrypt(Uint8List ivAndBytes,
      {Uint8List? publicKey}) async {
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

    var symmetricKey = Uint8List.fromList(derivedKeyBytes);

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

  /// Converts the Ed25519 key to an X25519 public key.
  Future<Uint8List> ed25519KeyToX25519PublicKey() async {
    // Get the Ed25519 public key
    final ed25519PublicKey = ed.public(_privateKey);

    // Convert Ed25519 public key to X25519 public key
    // The conversion function returns the X25519 public key bytes directly
    final x25519PublicKeyBytes =
        ed25519PublicToX25519Public(ed25519PublicKey.bytes);

    // Return the X25519 public key bytes directly
    return x25519PublicKeyBytes;
  }
}
