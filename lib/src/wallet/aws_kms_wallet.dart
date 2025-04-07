import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;

import '../key_pair/aws_kms_key_pair.dart';
import '../types.dart';
import 'wallet.dart';

class KmsWallet implements Wallet {
  final kms.KMS kmsClient;

  KmsWallet(this.kmsClient);

  @override
  Future<Uint8List> sign(Uint8List data, {required String keyId}) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.sign(data);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
  }) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.verify(data, signature);
  }

  @override
  Future<Uint8List> getPublicKey(String keyId) async {
    final keyPair = await getKeyPair(keyId);
    return keyPair.publicKey;
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
  Future<KmsKeyPair> createKeyPair(
    String keyId, {
    KeyType? keyType,
  }) async {
    final response = await kmsClient.createKey(
      keyUsage: kms.KeyUsageType.signVerify,
      customerMasterKeySpec: kms.CustomerMasterKeySpec.rsa_2048,
    );
    final newKeyId = response.keyMetadata?.keyId ?? '';
    return KmsKeyPair(kmsClient, newKeyId);
  }

  @override
  Future<KmsKeyPair> getKeyPair(String keyId) async {
    return KmsKeyPair(kmsClient, keyId);
  }
}
