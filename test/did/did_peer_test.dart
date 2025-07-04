import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:bip32_plus/bip32_plus.dart';
import 'package:ssi/src/utility.dart';
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

      final did = DidPeer.getDid(
        verificationMethods: [accountPublicKey],
        relationships: {
          VerificationRelationship.authentication: [0]
        },
      );
      final doc = DidPeer.resolve(did);
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

      final actualDid = DidPeer.getDid(
        verificationMethods: [accountPublicKey],
        relationships: {
          VerificationRelationship.authentication: [0]
        },
      );

      expect(actualDid, expectedDid);
    });

    test('generate and resolve did:peer:2 with one service endpoint', () async {
      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);

      final service = ServiceEndpoint(
        id: '#my-service',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );

      final did = DidPeer.getDid(
        verificationMethods: [key.publicKey],
        relationships: {
          VerificationRelationship.authentication: [0],
          VerificationRelationship.keyAgreement: [0]
        },
        serviceEndpoints: [service],
      );

      final resolvedDoc = DidPeer.resolve(did);
      expect(resolvedDoc.id, did);
      expect(resolvedDoc.service, isNotNull);
      expect(resolvedDoc.service.length, 1);
      expect(resolvedDoc.service[0].id, '#my-service');
      expect(resolvedDoc.service[0].type, 'TestService');
      expect(
        (resolvedDoc.service[0].serviceEndpoint as StringEndpoint).url,
        'https://example.com/endpoint',
      );
    });

    test('generate and resolve did:peer:2 with multiple service endpoints',
        () async {
      final authKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
      final agreeKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/1'");

      final service1 = ServiceEndpoint(
        id: '#service-1',
        type: 'DIDCommMessaging',
        serviceEndpoint: const StringEndpoint('https://endpoint1.com'),
      );

      final service2 = ServiceEndpoint(
        id: '#service-2',
        type: 'DIDCommMessaging',
        serviceEndpoint: const MapEndpoint({'uri': 'https://endpoint2.com'}),
      );

      final did = DidPeer.getDid(
        verificationMethods: [authKey.publicKey, agreeKey.publicKey],
        relationships: {
          VerificationRelationship.authentication: [0],
          VerificationRelationship.keyAgreement: [1]
        },
        serviceEndpoints: [service1, service2],
      );

      final resolvedDoc = DidPeer.resolve(did);

      expect(resolvedDoc.id, did);
      expect(resolvedDoc.service, isNotNull);
      expect(resolvedDoc.service.length, 2);
      expect(resolvedDoc.service[0].id, '#service-1');
      expect(resolvedDoc.service[0].type, 'DIDCommMessaging');
      expect(
        (resolvedDoc.service[0].serviceEndpoint as StringEndpoint).url,
        'https://endpoint1.com',
      );
      expect(resolvedDoc.service[1].id, '#service-2');
      expect(resolvedDoc.service[1].type, 'DIDCommMessaging');
      expect(
        (resolvedDoc.service[1].serviceEndpoint as MapEndpoint).data,
        {'uri': 'https://endpoint2.com'},
      );
    });

    test('generateDocument for did:peer:2 with separate keyAgreement keys',
        () async {
      final derivedKeyPath1 = "m/44'/60'/$accountNumber'/0'/0'";
      final derivedKeyPath2 = "m/44'/60'/$accountNumber'/0'/1'";

      final authKey = await wallet.generateKey(keyId: derivedKeyPath1);
      final agreeKey = await wallet.generateKey(keyId: derivedKeyPath2);

      final service = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );

      final did = DidPeer.getDid(
        verificationMethods: [authKey.publicKey, agreeKey.publicKey],
        relationships: {
          VerificationRelationship.authentication: [0],
          VerificationRelationship.keyAgreement: [1]
        },
        serviceEndpoints: [service],
      );
      final doc = DidPeer.resolve(did);

      // Check that keyAgreement contains only the agreement key
      expect(doc.keyAgreement.length, 1);

      // Check that authentication contains only the auth key
      expect(doc.authentication.length, 1);

      // Verify the DID contains both E and V prefixed keys
      expect(doc.id, contains('.Vz')); // Authentication key (V prefix)
      expect(doc.id, contains('.Ez')); // Agreement key (E prefix)
      expect(doc.id, contains('.S')); // Service (S prefix)

      // Verify verification methods are created correctly
      expect(doc.verificationMethod.length, 2);
      expect(doc.verificationMethod[0].id, '#key-1');
      expect(doc.verificationMethod[1].id, '#key-2');
    });

    test(
        'getDid for did:peer:2 should produce a resolvable document with correct structure',
        () async {
      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final keyPair =
          await wallet.generateKey(keyId: derivedKeyPath) as Ed25519KeyPair;
      final authPublicKey = keyPair.publicKey;
      final agreePublicKey = await keyPair.ed25519KeyToX25519PublicKey();

      final service = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://denys.com/income'),
      );

      // Simulate what the controller does: one public key per purpose instance.
      final verificationMethods = [
        authPublicKey,
        authPublicKey,
        agreePublicKey,
        agreePublicKey,
      ];
      final relationships = {
        VerificationRelationship.authentication: [0, 1],
        VerificationRelationship.keyAgreement: [2, 3],
      };

      final actualDid = DidPeer.getDid(
        verificationMethods: verificationMethods,
        relationships: relationships,
        serviceEndpoints: [service],
      );

      final resolvedDoc = DidPeer.resolve(actualDid);

      expect(resolvedDoc.id, actualDid);
      expect(resolvedDoc.authentication, hasLength(2));
      expect(resolvedDoc.keyAgreement, hasLength(2));
      expect(resolvedDoc.verificationMethod, hasLength(4));
      expect(resolvedDoc.service, hasLength(1));
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

      final did = DidPeer.getDid(verificationMethods: [
        accountPublicKey
      ], relationships: {
        VerificationRelationship.authentication: [0]
      });
      final doc = DidPeer.resolve(did);
      final actualPublicKey = doc.verificationMethod[0].asMultiKey();

      expect(actualPublicKey, expectedPublicKey);
    });

    test(
        'generateDocument for did:peer:2 should have correct verification relationships and context',
        () async {
      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);

      final service = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );

      final did = DidPeer.getDid(verificationMethods: [
        key.publicKey,
        PublicKey(key.id, ed25519PublicToX25519Public(key.publicKey.bytes),
            KeyType.x25519)
      ], relationships: {
        VerificationRelationship.authentication: [0],
        VerificationRelationship.keyAgreement: [1]
      }, serviceEndpoints: [
        service
      ]);
      final doc = DidPeer.resolve(did);

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
      expect(verificationMethods.length, 2); // 1 agreement, 1 authentication
      for (final vm in verificationMethods) {
        expect(vm.type, 'Multikey');
        expect(vm.controller, actualDid);
        expect(vm.id, startsWith('#key-'));
      }

      // Assert authentication, assertionMethod, keyAgreement
      final authenticationIds =
          resolvedDidDocument.authentication.map((vm) => vm.id).toList();
      final keyAgreementIds =
          resolvedDidDocument.keyAgreement.map((vm) => vm.id).toList();
      // By construction, last two keys are authentication/assertion, first two are keyAgreement
      expect(authenticationIds, ['#key-1']);
      expect(keyAgreementIds, ['#key-2']);

      // Assert capabilityDelegation and capabilityInvocation are empty
      expect(resolvedDidDocument.assertionMethod, isEmpty);
      expect(resolvedDidDocument.capabilityDelegation, isEmpty);
      expect(resolvedDidDocument.capabilityInvocation, isEmpty);

      // Assert service endpoint
      expect(resolvedDidDocument.service.length, 1);
    });

    test('generateDocument for did:peer:0 with P256 key', () async {
      // Generate a P256 key pair from a fixed seed for reproducibility
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final p256KeyPair = P256KeyPair.fromSeed(seed);

      final did = DidPeer.getDid(verificationMethods: [
        p256KeyPair.publicKey
      ], relationships: {
        VerificationRelationship.authentication: [0],
      });
      final doc = DidPeer.resolve(did);

      final actualDid = doc.id;
      final resolvedDidDocument = DidPeer.resolve(actualDid);

      // Assert context
      final context = resolvedDidDocument.context.toJson();
      expect(context, contains('https://www.w3.org/ns/did/v1'));
      expect(context, contains('https://w3id.org/security/multikey/v1'));

      // Assert key type
      expect(resolvedDidDocument.id, startsWith('did:peer:0zDn'));

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
      final did = DidPeer.getDid(verificationMethods: [
        secp256k1KeyPair.publicKey
      ], relationships: {
        VerificationRelationship.authentication: [0],
      });
      final doc = DidPeer.resolve(did);
      final actualDid = doc.id;
      final resolvedDidDocument = DidPeer.resolve(actualDid);

      // Assert context
      final context = resolvedDidDocument.context.toJson();
      expect(context, contains('https://www.w3.org/ns/did/v1'));
      expect(context, contains('https://w3id.org/security/multikey/v1'));

      // Assert key type
      expect(resolvedDidDocument.id, startsWith('did:peer:0zQ3s'));

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
