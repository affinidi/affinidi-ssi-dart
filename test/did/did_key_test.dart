import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
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
    late PublicKey accountPublicKey;

    setUp(() async {
      wallet = Bip32Wallet.fromSeed(seed);
      accountPublicKey =
          (await wallet.generateKey(keyId: "m/44'/60'/0'/0/0")).publicKey;
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
      final key = await wallet.generateKey(keyId: derivedKeyPath);
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

  group('Verification Method Format', () {
    late PublicKey publicKey;

    setUp(() async {
      final (keyPair, _) = Ed25519KeyPair.generate();
      publicKey = keyPair.publicKey;
    });

    test('should generate Ed25519VerificationKey2020 with multibase by default',
        () async {
      final doc = DidKey.generateDocument(publicKey);

      // Should have 2 verification methods: Ed25519 for signing and X25519 for key agreement
      expect(doc.verificationMethod, hasLength(2));

      // Find the Ed25519 verification method
      final ed25519Vm = doc.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));

      // Verify it uses the 2020 spec with multibase format
      expect(ed25519Vm.type, equals('Ed25519VerificationKey2020'));
      expect(ed25519Vm, isA<VerificationMethodMultibase>());

      final multibaseVm = ed25519Vm as VerificationMethodMultibase;
      expect(multibaseVm.publicKeyMultibase, startsWith('z'));
    });

    test(
        'should generate Ed25519VerificationKey2018 with explicit jwk2018 format',
        () async {
      final doc = DidKey.generateDocument(
        publicKey,
        format: Ed25519VerificationMethodFormat.jwk2018,
      );

      final ed25519Vm = doc.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));

      expect(ed25519Vm.type, equals('Ed25519VerificationKey2018'));
      expect(ed25519Vm, isA<VerificationMethodJwk>());
    });

    test('should generate Ed25519VerificationKey2020 with multibase2020 format',
        () async {
      final doc = DidKey.generateDocument(
        publicKey,
        format: Ed25519VerificationMethodFormat.multibase2020,
      );

      final ed25519Vm = doc.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));

      expect(ed25519Vm.type, equals('Ed25519VerificationKey2020'));
      expect(ed25519Vm, isA<VerificationMethodMultibase>());

      final multibaseVm = ed25519Vm as VerificationMethodMultibase;
      expect(multibaseVm.publicKeyMultibase, startsWith('z'));
    });

    test('both formats should encode the same key material', () async {
      final doc2018 = DidKey.generateDocument(
        publicKey,
        format: Ed25519VerificationMethodFormat.jwk2018,
      );
      final doc2020 = DidKey.generateDocument(
        publicKey,
        format: Ed25519VerificationMethodFormat.multibase2020,
      );

      // Both should generate the same DID
      expect(doc2018.id, equals(doc2020.id));

      // Extract the Ed25519 verification methods
      final vm2018 = doc2018.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));
      final vm2020 = doc2020.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));

      // Convert both to multikey format and compare
      final multikey2018 = vm2018.asMultiKey();
      final multikey2020 = vm2020.asMultiKey();

      expect(multikey2018, equals(multikey2020));

      // Convert both to JWK format and compare
      final jwk2018 = vm2018.asJwk();
      final jwk2020 = vm2020.asJwk();

      expect(jwk2018.toJson(), equals(jwk2020.toJson()));
    });

    test('resolve should use the specified format', () async {
      final did = DidKey.getDid(publicKey);

      // Resolve with default format (multibase2020)
      final doc2020 = DidKey.resolve(did);
      final vm2020 = doc2020.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));
      expect(vm2020.type, equals('Ed25519VerificationKey2020'));

      // Resolve with jwk2018 format
      final doc2018 = DidKey.resolve(
        did,
        format: Ed25519VerificationMethodFormat.jwk2018,
      );
      final vm2018 = doc2018.verificationMethod
          .firstWhere((vm) => vm.type.contains('Ed25519'));
      expect(vm2018.type, equals('Ed25519VerificationKey2018'));
    });

    test('X25519 key agreement format should match Ed25519 format', () async {
      // Test 2018 format uses X25519KeyAgreementKey2019 with publicKeyBase58
      final doc2018 = DidKey.generateDocument(
        publicKey,
        format: Ed25519VerificationMethodFormat.jwk2018,
      );

      final x25519Vm2018 = doc2018.verificationMethod
          .firstWhere((vm) => vm.type.contains('X25519'));

      expect(x25519Vm2018.type, equals('X25519KeyAgreementKey2019'));
      expect(x25519Vm2018, isA<VerificationMethodBase58>());

      // Test 2020 format uses X25519KeyAgreementKey2020 with publicKeyMultibase
      final doc2020 = DidKey.generateDocument(
        publicKey,
        format: Ed25519VerificationMethodFormat.multibase2020,
      );

      final x25519Vm2020 = doc2020.verificationMethod
          .firstWhere((vm) => vm.type.contains('X25519'));

      expect(x25519Vm2020.type, equals('X25519KeyAgreementKey2020'));
      expect(x25519Vm2020, isA<VerificationMethodMultibase>());

      // Both should encode the same X25519 key material
      final multikey2018 = x25519Vm2018.asMultiKey();
      final multikey2020 = x25519Vm2020.asMultiKey();
      expect(multikey2018, equals(multikey2020));
    });
  });
}
