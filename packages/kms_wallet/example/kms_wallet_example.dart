import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:shared_aws_api/shared.dart';
import 'package:kms_wallet/kms_wallet.dart';

void main() async {
  final yourKeyId = 'alias/test-key';
  final yourDataToSign = 'data';
  final accessKey = 'test';
  final secretKey = 'test';
  final region = 'ap-southeast-1';
  final endpointUrl = 'http://localhost:4566';

  final testData = Uint8List.fromList(yourDataToSign.codeUnits);

  final credentials =
      AwsClientCredentials(accessKey: accessKey, secretKey: secretKey);

  final kmsClient = kms.KMS(
    region: region,
    credentials: credentials,
    endpointUrl: endpointUrl,
  );

  final wallet = KmsWallet(kmsClient);

  final keyPair = await wallet.createKeyPair(yourKeyId);
  final keyId = keyPair.keyId;

  final signature = await wallet.sign(testData, keyId: keyId);
  final isValid =
      await wallet.verify(testData, signature: signature, keyId: keyId);

  print('Check if signature is valid: $isValid');
}
