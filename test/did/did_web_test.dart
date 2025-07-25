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
}
