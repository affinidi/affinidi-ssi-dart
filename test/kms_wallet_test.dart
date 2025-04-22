import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:shared_aws_api/shared.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import 'kms_wallet/kms_wallet.dart';

void main() {
  group('Test KmsWallet', () {
    late Wallet wallet;
    late PublicKey publicKey;
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
      publicKey = await wallet.generateKey();
    });

    test('Verifies data with valid signature', () async {
      final signature = await wallet.sign(testData, keyId: publicKey.id);
      final isValid = await wallet.verify(testData,
          signature: signature, keyId: publicKey.id);

      expect(isValid, isTrue);
    });

    test('Fails verification with invalid signature', () async {
      final invalidSignature = Uint8List.fromList(List.filled(256, 0));
      final isValid = await wallet.verify(testData,
          signature: invalidSignature, keyId: publicKey.id);

      expect(isValid, isFalse);
    });
  });
}
