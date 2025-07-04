import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:bip32_plus/bip32_plus.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

void main() {
  final seed = hexDecode(
    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    late Bip32Ed25519Wallet wallet;
    late PublicKey accountPublicKey;

    setUp(() async {
      wallet = Bip32Ed25519Wallet.fromSeed(seed);
      accountPublicKey =
          (await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'")).publicKey;
    });

    test('generateDocument for did:peer:0 should match expected', () async {
      final expectedDid =
          'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';
      final expectedKeyType = KeyType.ed25519;

      final doc = DidPeer.generateDocument([accountPublicKey]);
      final actualDid = doc.id;
      final actualKeyType = accountPublicKey.type;

      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerPeer);
      final resolvedDidDocument = DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('getDid for did:peer:0 should match expected', () async {
      final expectedDid =
          'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';

      final actualDid = DidPeer.getDid([accountPublicKey]);

      expect(actualDid, expectedDid);
    });

    test(
        'Resolve did document for did:peer:0 secp256k1 multikey should match expected',
        () async {
      final expectedDoc = DidDocument.fromJson(
          DidDocumentFixtures.didDocumentDidPeer0Secp256MultiKey);

      final doc = DidPeer.resolve(expectedDoc.id);

      expect(expectedDoc.id, doc.id);
      expect(
        doc.verificationMethod[0].id,
        expectedDoc.verificationMethod[0].id,
      );
      expect(doc.verificationMethod[0].type, 'Multikey');
    });

    test('generateDocument for did:peer:2 should start with did:peer:2.Ez6Mk',
        () async {
      final expectedDidPeerPrefix = 'did:peer:2.Ez6Mk';

      final expectedDid =
          'did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);
      final doc = DidPeer.generateDocument(
        [key.publicKey, key.publicKey],
        serviceEndpoint: 'https://denys.com/income',
      );
      final actualDid = doc.id;

      final expectedDidDocString =
          '{"id":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","@context":["https://www.w3.org/ns/did/v1","https://ns.did.ai/suites/multikey-2021/v1/"],"verificationMethod":[{"id":"#key-1","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-2","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-3","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-4","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"}],"authentication":["#key-3","#key-4"],"keyAgreement":["#key-1","#key-2"],"assertionMethod":["#key-3","#key-4"],"service":[{"id":"new-id","type":"DIDCommMessaging","serviceEndpoint":"https://denys.com/income"}]}';
      final resolvedDidDocument = DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), jsonDecode(expectedDidDocString));

      expect(actualDid, startsWith(expectedDidPeerPrefix));
    });

    test('getDid for did:peer:2 should match expected', () async {
      final expectedDid =
          'did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);
      final actualDid = DidPeer.getDid(
        [
          key.publicKey,
          key.publicKey
        ], // Using same key twice for simplicity, matching generateDocument test
        serviceEndpoint: 'https://denys.com/income',
      );

      expect(actualDid, expectedDid);
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey = Uint8List.fromList([
        237,
        1,
        56,
        162,
        237,
        26,
        224,
        161,
        48,
        164,
        81,
        159,
        5,
        116,
        7,
        215,
        243,
        177,
        23,
        231,
        108,
        55,
        87,
        112,
        225,
        15,
        181,
        233,
        26,
        194,
        131,
        237,
        234,
        165
      ]);

      final doc = DidPeer.generateDocument([accountPublicKey]);
      final actualPublicKey = doc.verificationMethod[0].asMultiKey();

      expect(actualPublicKey, expectedPublicKey);
    });

    test(
        'generateDocument for did:peer:2 should have correct verification relationships and context',
        () async {
      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);
      final doc = DidPeer.generateDocument(
        [key.publicKey, key.publicKey],
        serviceEndpoint: 'https://denys.com/income',
      );
      final actualDid = doc.id;
      final resolvedDidDocument = DidPeer.resolve(actualDid);

      // Assert context
      final context = resolvedDidDocument.context.toJson();
      expect(context, contains('https://www.w3.org/ns/did/v1'));
      expect(
          context,
          anyOf(
            contains('https://www.w3.org/ns/did/v1'),
            contains('https://w3id.org/security/suites/multikey-2021/v1'),
          ));

      // Assert verificationMethod
      final verificationMethods = resolvedDidDocument.verificationMethod;
      expect(verificationMethods.length, 4); // 2 agreement, 2 authentication
      for (final vm in verificationMethods) {
        expect(vm.type, 'Multikey');
        expect(vm.controller, actualDid);
        expect(vm.id, startsWith('#key-'));
      }

      // Assert authentication, assertionMethod, keyAgreement
      final authenticationIds =
          resolvedDidDocument.authentication.map((vm) => vm.id).toList();
      final assertionIds =
          resolvedDidDocument.assertionMethod.map((vm) => vm.id).toList();
      final keyAgreementIds =
          resolvedDidDocument.keyAgreement.map((vm) => vm.id).toList();
      // By construction, last two keys are authentication/assertion, first two are keyAgreement
      expect(authenticationIds, ['#key-3', '#key-4']);
      expect(assertionIds, ['#key-3', '#key-4']);
      expect(keyAgreementIds, ['#key-1', '#key-2']);

      // Assert capabilityDelegation and capabilityInvocation are empty
      expect(resolvedDidDocument.capabilityDelegation, isEmpty);
      expect(resolvedDidDocument.capabilityInvocation, isEmpty);

      // Assert service endpoint
      expect(resolvedDidDocument.service.length, 1);
    });

    test('generateDocument for did:peer:0 with P256 key', () async {
      // Generate a P256 key pair from a fixed seed for reproducibility
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final p256KeyPair = P256KeyPair.fromSeed(seed);
      final doc = DidPeer.generateDocument([p256KeyPair.publicKey]);
      final actualDid = doc.id;
      final resolvedDidDocument = DidPeer.resolve(actualDid);

      // Assert context
      final context = resolvedDidDocument.context.toJson();
      expect(context, contains('https://www.w3.org/ns/did/v1'));
      expect(
          context,
          anyOf(
            contains('https://www.w3.org/ns/did/v1'),
            contains('https://w3id.org/security/suites/multikey-2021/v1'),
          ));

      // Assert verificationMethod
      final verificationMethods = resolvedDidDocument.verificationMethod;
      expect(verificationMethods.length, 1);
      expect(verificationMethods[0].type, 'Multikey');
      expect(verificationMethods[0].controller, actualDid);

      // Assert relationships
      expect(resolvedDidDocument.authentication.length, 1);
      expect(resolvedDidDocument.assertionMethod.length, 1);
      expect(resolvedDidDocument.capabilityDelegation.length, 1);
      expect(resolvedDidDocument.capabilityInvocation.length, 1);
      expect(
          resolvedDidDocument.authentication[0].id, verificationMethods[0].id);
      expect(
          resolvedDidDocument.assertionMethod[0].id, verificationMethods[0].id);
      expect(resolvedDidDocument.capabilityDelegation[0].id,
          verificationMethods[0].id);
      expect(resolvedDidDocument.capabilityInvocation[0].id,
          verificationMethods[0].id);
    });

    test('generateDocument for did:peer:0 with Secp256k1 key', () async {
      // Generate a Secp256k1 key pair from a fixed seed for reproducibility
      final seed = Uint8List.fromList(List.generate(32, (i) => 100 + i));
      final node = BIP32.fromSeed(seed);
      final secp256k1KeyPair = Secp256k1KeyPair(node: node);
      final doc = DidPeer.generateDocument([secp256k1KeyPair.publicKey]);
      final actualDid = doc.id;
      final resolvedDidDocument = DidPeer.resolve(actualDid);

      // Assert context
      final context = resolvedDidDocument.context.toJson();
      expect(context, contains('https://www.w3.org/ns/did/v1'));
      expect(
          context,
          anyOf(
            contains(
              'https://www.w3.org/ns/did/v1',
            ),
            contains('https://w3id.org/security/suites/multikey-2021/v1'),
          ));

      // Assert verificationMethod
      final verificationMethods = resolvedDidDocument.verificationMethod;
      expect(verificationMethods.length, 1);
      expect(verificationMethods[0].type, 'Multikey');
      expect(verificationMethods[0].controller, actualDid);

      // Assert relationships
      expect(resolvedDidDocument.authentication.length, 1);
      expect(resolvedDidDocument.assertionMethod.length, 1);
      expect(resolvedDidDocument.capabilityDelegation.length, 1);
      expect(resolvedDidDocument.capabilityInvocation.length, 1);
      expect(
          resolvedDidDocument.authentication[0].id, verificationMethods[0].id);
      expect(
          resolvedDidDocument.assertionMethod[0].id, verificationMethods[0].id);
      expect(resolvedDidDocument.capabilityDelegation[0].id,
          verificationMethods[0].id);
      expect(resolvedDidDocument.capabilityInvocation[0].id,
          verificationMethods[0].id);
    });
  });
}
