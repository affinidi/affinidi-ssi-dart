import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import './_encryption_utils.dart';

/// The length of a compressed public key.
const compressedPublicKeyLength = 32;

/// A static nonce used for HKDF key derivation.
final staticHkdNonce = Uint8List(12); // Use a nonce (e.g., 12-byte for AES-GCM)

/// The encryption utils instance.
final encryptionUtils = EncryptionUtils();

// Gets the length of the non-compressed public key for the given curve.
/// This is used to determine how many bytes to read for the public key in the encrypted package.

int getNonCompressedPublicKeyLength(Curve curve) {
  final name = curve.name.toLowerCase();

  // NIST and secp curves (uncompressed: 1-byte prefix + X + Y coordinates)
  if (name == 'secp256r1' || name == 'p-256') return 65; // 1 + 32 + 32
  if (name == 'secp256k1' || name == 'p-256k1') return 65; // 1 + 32 + 32
  if (name == 'secp384r1' || name == 'p-384') return 97; // 1 + 48 + 48
  if (name == 'secp521r1' || name == 'p-521') return 133; // 1 + 66 + 66

  // Ed25519 and X25519 (no uncompressed format, always 32 bytes)
  if (name == 'ed25519' || name == 'x25519') return 32;

  throw ArgumentError('Unsupported curve: ${curve.name}');
}

/// Generates an ephemeral public key for the given curve.
PublicKey generateEphemeralPubKey(Curve curve) {
  final privateKey = curve.generatePrivateKey();
  return curve.privateToPublicKey(privateKey);
}

/// Computes the ECDH shared secret.
Future<Uint8List> computeEcdhSecret(
    PrivateKey privateKey, PublicKey publicKey) async {
  final secret = computeSecret(privateKey, publicKey);
  return Uint8List.fromList(secret);
}

/// Encrypts data using ECDH and AES-GCM.
Future<Uint8List> encryptData({
  required Uint8List data,
  required Uint8List privateKeyBytes,
  required Curve curve,
  Uint8List? publicKeyBytes,
}) async {
  final privateKey = PrivateKey.fromBytes(curve, privateKeyBytes);
  PublicKey publicKeyToUse;

  try {
    publicKeyToUse = publicKeyBytes == null
        ? generateEphemeralPubKey(curve)
        : curve.compressedHexToPublicKey(hex.encode(publicKeyBytes));
  } catch (e) {
    throw SsiException(
      message: 'Invalid public Key',
      code: SsiExceptionType.unableToEncrypt.code,
      originalMessage: e.toString(),
    );
  }

  final sharedSecret = await computeEcdhSecret(privateKey, publicKeyToUse);

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
  final symmetricKey = Uint8List.fromList(derivedKeyBytes);

  final encryptedData = encryptionUtils.encryptToBytes(symmetricKey, data);
  final publicKeyToUseBytes = hex.decode(publicKeyToUse.toHex());

  return Uint8List.fromList(publicKeyToUseBytes + encryptedData);
}

/// Decrypts data using ECDH and AES-GCM.
Future<Uint8List> decryptData({
  required Uint8List encryptedPackage,
  required Uint8List privateKeyBytes,
  required Curve curve,
  Uint8List? publicKeyBytes,
}) async {
  final privateKey = PrivateKey.fromBytes(curve, privateKeyBytes);
  final publicKeyLen = getNonCompressedPublicKeyLength(curve);
  final ephemeralPublicKeyBytes = encryptedPackage.sublist(0, publicKeyLen);
  final encryptedData = encryptedPackage.sublist(publicKeyLen);

  final pubKeyToUse = publicKeyBytes == null
      ? curve.hexToPublicKey(hex.encode(ephemeralPublicKeyBytes))
      : curve.compressedHexToPublicKey(hex.encode(publicKeyBytes));

  final sharedSecret = await computeEcdhSecret(privateKey, pubKeyToUse);

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
  final symmetricKey = Uint8List.fromList(derivedKeyBytes);

  final decryptedData =
      encryptionUtils.decryptFromBytes(symmetricKey, encryptedData);

  if (decryptedData == null) {
    throw SsiException(
      message: 'Decryption failed, bytes are null',
      code: SsiExceptionType.unableToDecrypt.code,
    );
  }

  return decryptedData;
}
