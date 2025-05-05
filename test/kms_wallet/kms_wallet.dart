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
    final keyPair = await getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.verify(data, signature, signatureScheme: signatureScheme);
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(
      String keyId) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.supportedSignatureSchemes;
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    final keyData = keyPair.publicKey;
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
  Future<KeyPair> generateKey({
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
    return KmsKeyPair.generate(kmsClient, newKeyId);
  }

  @override
  Future<Uint8List> encrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    throw UnimplementedError();
  }

  @override
  Future<KmsKeyPair> getKeyPair(String keyId) async {
    return KmsKeyPair.generate(kmsClient, keyId);
  }
}
