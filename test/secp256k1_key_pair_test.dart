import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:affinidi_ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test signature and verification', () {
    test('the main key pair should sign data and verify signature', () async {
      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";

      final signature = await wallet.sign(dataToSign, keyId: rootKeyId);

      final actual = await wallet.verify(
        dataToSign,
        signature: signature,
        keyId: rootKeyId,
      );

      expect(actual, isTrue);
    });

    test('the derived key pair should sign data and verify signature',
        () async {
      final accountNumber = 1234;
      final wallet = Bip32Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final keyPair = await wallet.deriveKeyPair(derivedKeyId);

      final signature = await keyPair.sign(dataToSign);

      final actual = await keyPair.verify(
        dataToSign,
        signature: signature,
      );

      expect(actual, isTrue);
    });

    test('should fail if signature is invalid', () async {
      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final signature = await wallet.sign(dataToSign, keyId: rootKeyId);

      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0]++;

      final actual = await wallet.verify(
        dataToSign,
        signature: invalidSignature,
        keyId: rootKeyId,
      );

      expect(actual, isFalse);
    });
  });
}
