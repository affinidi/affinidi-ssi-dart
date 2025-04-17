import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';
import 'package:cryptography/cryptography.dart' as crypto;

import './_encryption_utils.dart';

const fullPublicKeyLength = 64;
const compressedPublidKeyLength = 32;
final staticHkdNonce = Uint8List(12); // Use a nonce (e.g., 12-byte for AES-GCM)
final encryptionUtils = EncryptionUtils();

PublicKey generateEphemeralPubKey(Curve curve) {
  final privateKey = curve.generatePrivateKey();
  return curve.privateToPublicKey(privateKey);
}

Future<Uint8List> computeEcdhSecret(
    PrivateKey privateKey, PublicKey publicKey) async {
  final secret = computeSecret(privateKey, publicKey);
  return Uint8List.fromList(secret);
}

Future<Uint8List> encryptData({
  required Uint8List data,
  required Uint8List privateKeyBytes,
  required Curve curve,
  Uint8List? publicKeyBytes,
}) async {
  final privateKey = PrivateKey.fromBytes(curve, privateKeyBytes);

  final PublicKey publicKeyToUse = publicKeyBytes == null
      ? generateEphemeralPubKey(curve)
      : curve.compressedHexToPublicKey(hex.encode(publicKeyBytes));

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

  final PublicKey pubKeyToUse = publicKeyBytes == null
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
    throw UnimplementedError('Decryption failed, bytes are null');
  }

  return decryptedData;
}
