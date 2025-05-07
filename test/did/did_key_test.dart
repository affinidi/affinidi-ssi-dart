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
    late Bip32Wallet wallet;
    late InMemoryKeyStore keyStore;
    late PublicKey accountPublicKey;

    setUp(() async {
      keyStore = InMemoryKeyStore();
      wallet = await Bip32Wallet.fromSeed(seed, keyStore);
      accountPublicKey =
          (await wallet.deriveKey(derivationPath: "m/44'/60'/0'/0/0"))
              .publicKey;
    });

    test('generateDocument should match expected', () async {
      final expectedDid =
          'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';
      final expectedKeyType = KeyType.secp256k1;

      final doc = DidKey.generateDocument(accountPublicKey);
      final actualDid = doc.id;
      final actualKeyType = accountPublicKey.type;

      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);
      final resolvedDidDocument = DidKey.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('getDid should match expected', () async {
      final expectedDid =
          'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';

      final actualDid = DidKey.getDid(accountPublicKey);

      expect(actualDid, expectedDid);
    });

    test('generateDocument for derived key should start with did:key:zQ3s',
        () async {
      final expectedDidKeyPrefix = 'did:key:zQ3s';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0/0";
      final key = await wallet.deriveKey(derivationPath: derivedKeyPath);
      final doc = DidKey.generateDocument(key.publicKey);
      final actualDid = doc.id;

      expect(actualDid, startsWith(expectedDidKeyPrefix));
    });

    test(
        'generateDocument should be different if the wrong key type is provided',
        () async {
      final expectedDid =
          'did:key:zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      final expectedKeyType = KeyType.secp256k1;

      final doc = DidKey.generateDocument(accountPublicKey);
      final actualDid = doc.id;
      final actualKeyType = accountPublicKey.type;

      expect(actualDid, isNot(equals(expectedDid)));
      expect(actualKeyType, expectedKeyType);
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey = Uint8List.fromList([
        231,
        1,
        2,
        184,
        117,
        73,
        205,
        100,
        221,
        183,
        93,
        177,
        238,
        33,
        153,
        1,
        82,
        93,
        46,
        162,
        100,
        246,
        26,
        148,
        56,
        81,
        145,
        85,
        184,
        206,
        69,
        211,
        42,
        192,
        136
      ]);

      final doc = DidKey.generateDocument(accountPublicKey);
      final actualPublicKey = doc.verificationMethod[0].asMultiKey();

      expect(actualPublicKey, expectedPublicKey);
    });
  });

  group('did:key with P256', () {
    test('generateDocument is as expected', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = PersistentWallet(keyStore);
      final keyId = 'keyId';
      final publicKey = (await wallet.generateKey(keyId: keyId)).publicKey;
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

    test('getDid is as expected', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = PersistentWallet(keyStore);
      final keyId = 'keyId';
      final publicKey = (await wallet.generateKey(keyId: keyId)).publicKey;
      final prefix = [128, 36];
      final expectedId =
          'did:key:z${base58BitcoinEncode(Uint8List.fromList(prefix + publicKey.bytes))}';

      final actualId = DidKey.getDid(publicKey);
      expect(actualId, expectedId);
    });
  });

  group('When resolving did key with', () {
    group('using did:test', () {
      test('it throws invalid did key exception', () async {
        expect(
          () => DidKey.resolve('did:test:something'),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.invalidDidKey.code)),
        );
      });
    });

    group('using misformatted did', () {
      test('it throws invalid did key exception', () async {
        expect(
          () => DidKey.resolve('did:key:something:sometimes'),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.invalidDidKey.code)),
        );
      });
    });
  });
}
