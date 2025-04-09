import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';

import 'package:ssi/src/types.dart';
import 'package:ssi/src/wallet/wallet.dart';

import 'kms_key_pair.dart';

class KmsWallet implements Wallet {
  final kms.KMS kmsClient;

  KmsWallet(this.kmsClient);

  @override
  Future<Uint8List> sign(Uint8List data, {required String keyId}) async {
    try {
      final keyPair = await getKeyPair(keyId);
      return keyPair.sign(data);
    } catch (e, stackTrace) {
      Error.throwWithStackTrace(
        SsiException(
          message: 'Failed to sign data using KMS key.',
          originalMessage: e.toString(),
          code: SsiExceptionType.keyPairMissingPrivateKey.code,
        ),
        stackTrace,
      );
    }
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
  }) async {
    try {
      final keyPair = await getKeyPair(keyId);
      return keyPair.verify(data, signature);
    } catch (_) {
      return false;
    }
  }

  @override
  Future<Uint8List> getPublicKey(String keyId) async {
    try {
      final keyPair = await getKeyPair(keyId);
      return keyPair.publicKey;
    } catch (e, stackTrace) {
      Error.throwWithStackTrace(
        SsiException(
          message: 'Failed to get public key for KMS keyId: $keyId',
          originalMessage: e.toString(),
          code: SsiExceptionType.keyPairMissingPrivateKey.code,
        ),
        stackTrace,
      );
    }
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
    try {
      final response = await kmsClient.createKey(
        keyUsage: kms.KeyUsageType.signVerify,
        customerMasterKeySpec: kms.CustomerMasterKeySpec.rsa_2048,
      );
      final newKeyId = response.keyMetadata?.keyId;
      if (newKeyId == null || newKeyId.isEmpty) {
        throw SsiException(
          message: 'Key creation succeeded but keyId is null.',
          code: SsiExceptionType.other.code,
        );
      }
      return KmsKeyPair(kmsClient, newKeyId);
    } catch (e, stackTrace) {
      Error.throwWithStackTrace(
        SsiException(
          message: 'Failed to create KMS key pair.',
          originalMessage: e.toString(),
          code: SsiExceptionType.other.code,
        ),
        stackTrace,
      );
    }
  }

  @override
  Future<KmsKeyPair> getKeyPair(String keyId) async {
    return KmsKeyPair(kmsClient, keyId);
  }
}
