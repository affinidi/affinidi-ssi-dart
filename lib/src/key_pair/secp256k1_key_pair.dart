import 'dart:convert';
import 'package:convert/convert.dart';
import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:cryptography/cryptography.dart' as crypto;

import 'package:affinidi_tdk_cryptography/affinidi_tdk_cryptography.dart';

import '../digest_utils.dart';
import '../types.dart';
import 'key_pair.dart';

var STATIC_HKD_NONCE = Uint8List(12); // Use a nonce (e.g., 12-byte for AES-GCM)
var FULL_PUB_KEY_LENGTH = 64;

class Secp256k1KeyPair implements KeyPair {
  final String _keyId;
  final BIP32 _node;
  final CryptographyService _cryptographyService;
  var _secp256k1;

  Secp256k1KeyPair({
    required BIP32 node,
    required String keyId,
  })  : _node = node,
        _keyId = keyId,
        _cryptographyService = CryptographyService(),
        _secp256k1 = getSecp256k1();

  @override
  Future<String> get id => Future.value(_keyId);

  @override
  Future<Uint8List> get publicKey => Future.value(_node.publicKey);

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.secp256k1);

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_secp256k1_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_secp256k1_sha256) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only es256k is supported with secp256k1");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.sign(digest);
  }

  @override
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ecdsa_secp256k1_sha256;
    if (signatureScheme != SignatureScheme.ecdsa_secp256k1_sha256) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only es256k is supported with secp256k1");
    }
    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return _node.verify(digest, signature);
  }

  BIP32 getBip32Node() => _node;

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      [SignatureScheme.ecdsa_secp256k1_sha256];


  PublicKey generateEphemeralPubKey() {
    var privateKey = _secp256k1.generatePrivateKey();
    var publicKey = _secp256k1.privateToPublicKey(privateKey);
    return publicKey;
  }

  Future<Uint8List> computeEcdhSecret(PublicKey publicKey) async {
    var privateKey = PrivateKey.fromBytes(_secp256k1, _node.privateKey!);
    final secret = computeSecret(privateKey, publicKey);
    return Future.value(Uint8List.fromList(secret));
  }

  // @override
  encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = _node.privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    PublicKey publicKeyToUse;
    if (publicKey == null) {
      publicKeyToUse = await generateEphemeralPubKey();
    } else {
      publicKeyToUse = _secp256k1.compressedHexToPublicKey(hex.encode(publicKey));
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

    final encryptedData = await _cryptographyService.encryptToBytes(symmetricKey, data);

    var publicKeyToUseBytes = hex.decode(publicKeyToUse.toHex());

    return Uint8List.fromList(publicKeyToUseBytes + encryptedData);
  }


  // @override
  decrypt(Uint8List ivAndBytes, {Uint8List? publicKey}) async {
    final privateKey = _node.privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    // Extract the ephemeral public key and the encrypted data
    final ephemeralPublicKeyBytes = ivAndBytes.sublist(0, FULL_PUB_KEY_LENGTH + 1);
    final encryptedData = ivAndBytes.sublist(FULL_PUB_KEY_LENGTH + 1);  // The rest is the encrypted data

    var pubKeyToUse;
    if (publicKey == null) {
      var pubKeyToUseBytes = ephemeralPublicKeyBytes;
      var publicKeyHex = hex.encode(pubKeyToUseBytes);
      pubKeyToUse = _secp256k1.hexToPublicKey(publicKeyHex);
    } else {
      var pubKeyToUseBytes = publicKey;
      var publicKeyHex = hex.encode(pubKeyToUseBytes);
      pubKeyToUse = _secp256k1.compressedHexToPublicKey(publicKeyHex);
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

    final decryptedData = await _cryptographyService.decryptFromBytes(symmetricKey, encryptedData);

    if (decryptedData == null) {
      throw UnimplementedError('Decryption failed, bytes are null');
    }

    return decryptedData;
  }
}
