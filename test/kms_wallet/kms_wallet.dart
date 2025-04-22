import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:ssi/ssi.dart';

import 'kms_key_pair.dart';

class KmsWallet implements Wallet {
  final kms.KMS kmsClient;

  KmsWallet(this.kmsClient);

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.verify(data, signature, signatureScheme: signatureScheme);
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(
      String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.supportedSignatureSchemes;
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final keyData = await keyPair.publicKey;
    return Future.value(PublicKey(keyId, keyData.bytes, keyData.type));
  }

  @override
  Future<bool> hasKey(String keyId) async {
    try {
      await kmsClient.describeKey(keyId: keyId);
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<PublicKey> generateKey({
    String? keyId,
    KeyType? keyType,
  }) async {
    if (keyId != null) {
      throw ArgumentError(
          "AWS KMS creates the key identifiers. keyId should not be provided");
    }
    final response = await kmsClient.createKey(
      keyUsage: kms.KeyUsageType.signVerify,
      customerMasterKeySpec: kms.CustomerMasterKeySpec.rsa_2048,
    );
    final newKeyId = response.keyMetadata?.keyId ?? '';
    final keyPair = KmsKeyPair(kmsClient, newKeyId);

    final keyData = await keyPair.publicKey;
    return Future.value(PublicKey(newKeyId, keyData.bytes, keyData.type));
  }

  Future<KmsKeyPair> _getKeyPair(String keyId) async {
    return KmsKeyPair(kmsClient, keyId);
  }
}
