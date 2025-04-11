import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:shared_aws_api/shared.dart';
import 'package:ssi_kms_wallet/ssi_kms_wallet.dart';
import 'package:test/test.dart';

void main() {
  group('Test KmsWallet', () {
    var keyId;
    var keyPair;
    var wallet;
    final testKeyId = 'alias/test-key';
    final testData = Uint8List.fromList('test data'.codeUnits);

    setUp(() async {
      final credentials =
          AwsClientCredentials(accessKey: 'test', secretKey: 'test');

      final kmsClient = kms.KMS(
        region: 'ap-southeast-1',
        credentials: credentials,
        endpointUrl: 'http://localhost:4566',
      );

      wallet = KmsWallet(kmsClient);
      keyPair = await wallet.createKeyPair(testKeyId);
      keyId = keyPair.keyId;
    });

    test('Verifies data with valid signature', () async {
      final signature = await wallet.sign(testData, keyId: keyId);
      final isValid =
          await wallet.verify(testData, signature: signature, keyId: keyId);

      expect(isValid, isTrue);
    });

    test('Fails verification with invalid signature', () async {
      final invalidSignature = Uint8List.fromList(List.filled(256, 0));
      final isValid = await wallet.verify(testData,
          signature: invalidSignature, keyId: keyId);

      expect(isValid, isFalse);
    });
  });
}
