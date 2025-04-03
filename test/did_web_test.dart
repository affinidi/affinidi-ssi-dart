// import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    test('the main did key should match to the expected value', () async {
      final expectedDid = 'did:web:test.com';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final doc = await DidWeb.create([keyPair], 'did:web:test.com');
      final actualDid = doc.id;
      final actualKeyType = await keyPair.getKeyType();

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('a derived did keys should start with did:web', () async {
      final expectedDidWebPrefix = 'did:web';

      final wallet = Bip32Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final keyPair = await wallet.createKeyPair(derivedKeyId);
      final doc = await DidWeb.create([keyPair], 'did:web:test.com');
      final actualDid = doc.id;

      expect(actualDid, startsWith(expectedDidWebPrefix));
    });
  });
}
