import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final accountNumber = 24567;

  group('did:key with BIP32', () {
    test('the main did key should match to the expected value', () async {
      final expectedDid =
          'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final key = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
      final doc = DidKey.generateDocument(key);
      final actualDid = doc.id;
      final actualKeyType = key.type;

      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);
      final resolvedDidDocument = DidKey.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('a derived did keys should start with did:key:zQ3s', () async {
      final expectedDidKeyPrefix = 'did:key:zQ3s';

      final wallet = Bip32Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final key = await wallet.generateKey(keyId: derivedKeyId);
      final doc = DidKey.generateDocument(key);
      final actualDid = doc.id;

      expect(actualDid, startsWith(expectedDidKeyPrefix));
    });

    test('did should be different if the wrong key type is provided', () async {
      final expectedDid =
          'did:key:zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final key = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
      final doc = DidKey.generateDocument(key);
      final actualDid = doc.id;
      final actualKeyType = key.type;

      expect(actualDid, isNot(equals(expectedDid)));
      expect(actualKeyType, expectedKeyType);
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey = Uint8List.fromList([
        231,
        1,
        2,
        233,
        113,
        31,
        100,
        37,
        199,
        52,
        153,
        50,
        216,
        134,
        234,
        13,
        174,
        130,
        68,
        201,
        134,
        53,
        18,
        63,
        241,
        99,
        53,
        238,
        174,
        142,
        117,
        242,
        57,
        243,
        247,
      ]);

      final wallet = Bip32Wallet.fromSeed(seed);
      final key = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
      final doc = DidKey.generateDocument(key);
      final actualPublicKey = doc.verificationMethod[0].asMultiKey();

      expect(actualPublicKey, expectedPublicKey);
    });
  });

  group('did:key with P256', () {
    test('generated did document is as expected', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = GenericWallet(keyStore);
      final keyId = "keyId";
      final publicKey = await wallet.generateKey(keyId: keyId);
      final prefix = [128, 36];
      final expectedId =
          'did:key:z${base58BitcoinEncode(Uint8List.fromList(prefix + publicKey.bytes))}';
      final expectedDid = DidKey.resolve(expectedId);
      final expectedDidJson = expectedDid.toJson();
      final actualDid = DidKey.generateDocument(publicKey);
      final actualDidJson = actualDid.toJson();
      expect(actualDidJson, expectedDidJson);
      expect(actualDid.id.startsWith('did:key:zDn'), isTrue);
      expect(actualDid.verificationMethod.length, 1);
      expect(actualDid.verificationMethod[0].type, 'P256Key2021');
    });
  });

  group("When resolving did key with", () {
    group("using did:test", () {
      test("it throws invalid did key exception", () async {
        expect(
          () => DidKey.resolve("did:test:something"),
          throwsA(isA<SsiException>().having(
              (e) => e.code, "code", SsiExceptionType.invalidDidKey.code)),
        );
      });
    });

    group("using misformatted did", () {
      test("it throws invalid did key exception", () async {
        expect(
          () => DidKey.resolve("did:key:something:sometimes"),
          throwsA(isA<SsiException>().having(
              (e) => e.code, "code", SsiExceptionType.invalidDidKey.code)),
        );
      });
    });
  });
}
