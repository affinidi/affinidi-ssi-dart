import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import './_encryption_utils.dart';

/// The length of a full public key.
const fullPublicKeyLength = 64;

/// The length of a compressed public key.
const compressedPublidKeyLength = 32;

/// A static nonce used for HKDF key derivation.
final staticHkdNonce = Uint8List(12); // Use a nonce (e.g., 12-byte for AES-GCM)

/// The encryption utils instance.
final encryptionUtils = EncryptionUtils();

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

  final ephemeralPublicKeyBytes =
      encryptedPackage.sublist(0, fullPublicKeyLength + 1);
  final encryptedData = encryptedPackage.sublist(fullPublicKeyLength + 1);

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
