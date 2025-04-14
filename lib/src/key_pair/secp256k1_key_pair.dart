import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:affinidi_tdk_cryptography/affinidi_tdk_cryptography.dart';

import '../digest_utils.dart';
import '../types.dart';
import 'key_pair.dart';

class Secp256k1KeyPair implements KeyPair {
  final String _keyId;
  final BIP32 _node;
  final CryptographyService _cryptographyService;

  Secp256k1KeyPair({
    required BIP32 node,
    required String keyId,
  })  : _node = node,
        _keyId = keyId,
        _cryptographyService = CryptographyService();

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

  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = _node.privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }
    return _cryptographyService.encryptToBytes(privateKey, data);
  }

  @override
  Future<Uint8List> decrypt(Uint8List ivAndBytes, {Uint8List? publicKey}) async {
    final privateKey = _node.privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    final decryptedBytes = await _cryptographyService.decryptFromBytes(privateKey, ivAndBytes);
    if (decryptedBytes == null) {
      throw UnimplementedError('Decryption failed, bytes are null');
    }
    return decryptedBytes;
  }
}
