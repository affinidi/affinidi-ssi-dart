import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidWeb Resolution', () {
    test('converts did:web:example.com to expected URI', () {
      final uri = didWebToUri('did:web:example.com');
      expect(uri.toString(), 'https://example.com/.well-known/did.json');
    });

    test('converts nested did:web:example.com:user to correct URI', () {
      final uri = didWebToUri('did:web:example.com:user');
      expect(uri.toString(), 'https://example.com/user/did.json');
    });

    test('throws SsiException on non-200 response', () async {
      final did = 'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';

      await expectLater(
        DidWeb.resolve(did),
        throwsA(isA<SsiException>().having(
            (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
      );
    });
  });

  group('DidWeb Verification', () {
    test('should support Ed25519/EdDSA signatures', () async {
      // Mock DID document based on actual did:web:demo.spruceid.com response
      final mockDidDoc = DidDocument.fromJson({
        '@context': [
          'https://www.w3.org/ns/did/v1',
          {'@id': 'https://w3id.org/security#publicKeyJwk', '@type': '@json'}
        ],
        'assertionMethod': [
          'did:web:demo.spruceid.com#_t-v-Ep7AtkELhhvAzCCDzy1O5Bn_z1CVFv9yiRXdHY'
        ],
        'authentication': [
          'did:web:demo.spruceid.com#_t-v-Ep7AtkELhhvAzCCDzy1O5Bn_z1CVFv9yiRXdHY'
        ],
        'id': 'did:web:demo.spruceid.com',
        'verificationMethod': [
          {
            'controller': 'did:web:demo.spruceid.com',
            'id':
                'did:web:demo.spruceid.com#_t-v-Ep7AtkELhhvAzCCDzy1O5Bn_z1CVFv9yiRXdHY',
            'publicKeyJwk': {
              'crv': 'Ed25519',
              'kty': 'OKP',
              'x': '2yv3J-Sf263OmwDLS9uFPTRD0PzbvfBGKLiSnPHtXIU'
            },
            'type': 'Ed25519VerificationKey2018'
          }
        ]
      });

      final ed25519Vm = mockDidDoc.verificationMethod.first;
      final verifier = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: ed25519Vm.id,
        issuerDid: mockDidDoc.id,
      );

      expect(verifier.isAllowedAlgorithm('EdDSA'), isTrue);
      expect(verifier.isAllowedAlgorithm('Ed25519'), isTrue);
      expect(verifier.isAllowedAlgorithm('ES256K'), isFalse);
      expect(verifier.isAllowedAlgorithm('RS256'), isFalse);
    });

    test('should reject invalid signatures for Ed25519 keys', () async {
      // Mock DID document based on actual did:web:demo.spruceid.com response
      final mockDidDoc = DidDocument.fromJson({
        '@context': [
          'https://www.w3.org/ns/did/v1',
          {'@id': 'https://w3id.org/security#publicKeyJwk', '@type': '@json'}
        ],
        'id': 'did:web:demo.spruceid.com',
        'verificationMethod': [
          {
            'controller': 'did:web:demo.spruceid.com',
            'id':
                'did:web:demo.spruceid.com#_t-v-Ep7AtkELhhvAzCCDzy1O5Bn_z1CVFv9yiRXdHY',
            'publicKeyJwk': {
              'crv': 'Ed25519',
              'kty': 'OKP',
              'x': '2yv3J-Sf263OmwDLS9uFPTRD0PzbvfBGKLiSnPHtXIU'
            },
            'type': 'Ed25519VerificationKey2018'
          }
        ]
      });

      final vm = mockDidDoc.verificationMethod.first;
      final verifier = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: vm.id,
        issuerDid: mockDidDoc.id,
      );

      final testData = Uint8List.fromList(utf8.encode('Test data'));
      final fakeSignature = Uint8List.fromList(List.filled(64, 0));

      expect(verifier.verify(testData, fakeSignature), isFalse,
          reason: 'Should reject an obviously fake signature');

      final anotherFakeSignature = Uint8List.fromList(List.filled(64, 1));
      expect(verifier.verify(testData, anotherFakeSignature), isFalse,
          reason: 'Should reject another fake signature');
    });

    test('algorithm mismatch throws error', () async {
      // Mock DID document based on actual did:web:demo.spruceid.com response
      final mockDidDoc = DidDocument.fromJson({
        '@context': [
          'https://www.w3.org/ns/did/v1',
          {'@id': 'https://w3id.org/security#publicKeyJwk', '@type': '@json'}
        ],
        'id': 'did:web:demo.spruceid.com',
        'verificationMethod': [
          {
            'controller': 'did:web:demo.spruceid.com',
            'id':
                'did:web:demo.spruceid.com#_t-v-Ep7AtkELhhvAzCCDzy1O5Bn_z1CVFv9yiRXdHY',
            'publicKeyJwk': {
              'crv': 'Ed25519',
              'kty': 'OKP',
              'x': '2yv3J-Sf263OmwDLS9uFPTRD0PzbvfBGKLiSnPHtXIU'
            },
            'type': 'Ed25519VerificationKey2018'
          }
        ]
      });

      final vm = mockDidDoc.verificationMethod.first;

      void act() async {
        await DidVerifier.create(
          algorithm: SignatureScheme.ecdsa_p256_sha256,
          kid: vm.id,
          issuerDid: mockDidDoc.id,
        );
      }

      await expectLater(
        act,
        throwsA(
          isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.invalidDidDocument.code,
          ),
        ),
      );
    });
  });

  group('DidWeb.generateDocument', () {
    late PublicKey testPublicKey;

    setUp(() {
      // Create a mock public key for testing
      testPublicKey = PublicKey(
        'test-key-id',
        Uint8List.fromList(List.generate(32, (i) => i)),
        KeyType.ed25519,
      );
    });

    test('generates basic DID document with single key', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
          VerificationRelationship.assertionMethod: [vmId],
        },
        serviceEndpoints: [],
      );

      expect(doc.id, equals(did));
      expect(doc.verificationMethod.length, equals(1));
      expect(doc.verificationMethod.first.id, equals(vmId));
      expect(doc.authentication.length, equals(1));
      expect((doc.authentication.first as VerificationMethodRef).reference,
          equals(vmId));
      expect(doc.assertionMethod.length, equals(1));
      expect((doc.assertionMethod.first as VerificationMethodRef).reference,
          equals(vmId));
      expect(doc.service.length, equals(0));
    });

    test('generates DID document with multiple verification relationships', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
          VerificationRelationship.assertionMethod: [vmId],
          VerificationRelationship.keyAgreement: [vmId],
          VerificationRelationship.capabilityInvocation: [vmId],
          VerificationRelationship.capabilityDelegation: [vmId],
        },
        serviceEndpoints: [],
      );

      expect(doc.authentication.length, equals(1));
      expect(doc.assertionMethod.length, equals(1));
      expect(doc.keyAgreement.length, equals(1));
      expect(doc.capabilityInvocation.length, equals(1));
      expect(doc.capabilityDelegation.length, equals(1));
    });

    test('generates DID document with service endpoints', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';
      final serviceEndpoint = ServiceEndpoint(
        id: '$did#linked-domain',
        type: 'LinkedDomains',
        serviceEndpoint: const StringEndpoint('https://example.com/'),
      );

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
        },
        serviceEndpoints: [serviceEndpoint],
      );

      expect(doc.service.length, equals(1));
      expect(doc.service.first.id, equals('$did#linked-domain'));
      expect(doc.service.first.type, equals('LinkedDomains'));
    });

    test('generates DID document with multiple service endpoints', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';
      final services = [
        ServiceEndpoint(
          id: '$did#linked-domain',
          type: 'LinkedDomains',
          serviceEndpoint: const StringEndpoint('https://example.com/'),
        ),
        ServiceEndpoint(
          id: '$did#didcomm',
          type: 'DIDCommMessaging',
          serviceEndpoint: const StringEndpoint('https://example.com/didcomm'),
        ),
      ];

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
        },
        serviceEndpoints: services,
      );

      expect(doc.service.length, equals(2));
      expect(doc.service[0].type, equals('LinkedDomains'));
      expect(doc.service[1].type, equals('DIDCommMessaging'));
    });

    test('generates DID document for domain with port', () {
      final did = 'did:web:example.com%3A3000';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
        },
        serviceEndpoints: [],
      );

      expect(doc.id, equals(did));
      expect(doc.verificationMethod.first.controller, equals(did));
    });

    test('generates DID document for domain with path', () {
      final did = 'did:web:w3c-ccg.github.io:user:alice';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
        },
        serviceEndpoints: [],
      );

      expect(doc.id, equals(did));
      expect(doc.verificationMethod.first.id, equals(vmId));
    });

    test('generates DID document with correct context', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
        },
        serviceEndpoints: [],
      );

      final contextJson = doc.context.toJson();
      final contextList = contextJson is List ? contextJson : [contextJson];
      expect(contextList, contains('https://www.w3.org/ns/did/v1'));
      expect(contextList, contains('https://w3id.org/security/multikey/v1'));
    });

    test('generates verification method with Multikey type', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {
          VerificationRelationship.authentication: [vmId],
        },
        serviceEndpoints: [],
      );

      final vm = doc.verificationMethod.first as VerificationMethodMultibase;
      expect(vm.type, equals('Multikey'));
      expect(vm.controller, equals(did));
      expect(vm.publicKeyMultibase, isNotEmpty);
    });

    test('handles empty relationships', () {
      final did = 'did:web:example.com';
      final vmId = '$did#key-1';

      final doc = DidWeb.generateDocument(
        did: did,
        verificationMethodIds: [vmId],
        publicKeys: [testPublicKey],
        relationships: {},
        serviceEndpoints: [],
      );

      expect(doc.authentication.length, equals(0));
      expect(doc.assertionMethod.length, equals(0));
      expect(doc.keyAgreement.length, equals(0));
    });

    test(
        'throws ArgumentError when verification method IDs and keys length mismatch',
        () {
      final did = 'did:web:example.com';
      final vmId1 = '$did#key-1';
      final vmId2 = '$did#key-2';

      expect(
        () => DidWeb.generateDocument(
          did: did,
          verificationMethodIds: [vmId1, vmId2],
          publicKeys: [testPublicKey], // Only one key for two IDs
          relationships: {},
          serviceEndpoints: [],
        ),
        throwsArgumentError,
      );
    });
  });
}
