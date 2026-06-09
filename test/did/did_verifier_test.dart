import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

class MockDidResolver implements DidResolver {
  final DidDocument mockDocument;
  bool resolveCalled = false;
  String? lastDid;

  MockDidResolver(this.mockDocument);

  @override
  Future<DidDocument> resolveDid(String did) async {
    resolveCalled = true;
    lastDid = did;
    return mockDocument;
  }
}

class _FailingDidResolver implements DidResolver {
  @override
  Future<DidDocument> resolveDid(String did) async {
    throw SsiException(
      message: 'Test resolver failure',
      code: SsiExceptionType.unableToResolveDid.code,
    );
  }
}

void main() {
  group('DidVerifier', () {
    final didKey = 'did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';
    final kid = 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';

    test('should correctly handle algorithm support for Ed25519 keys',
        () async {
      final verifier = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: kid,
        issuerDid: didKey,
      );

      expect(verifier.isAllowedAlgorithm('EdDSA'), isTrue);
      expect(verifier.isAllowedAlgorithm('Ed25519'), isTrue);
      expect(verifier.isAllowedAlgorithm('ES256K'), isFalse);
      expect(verifier.isAllowedAlgorithm('RS256'), isFalse);
    });

    test('should reject invalid signatures for Ed25519 keys', () async {
      final verifier = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: kid,
        issuerDid: didKey,
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
      void act() async {
        await DidVerifier.create(
          algorithm: SignatureScheme.ecdsa_p256_sha256,
          kid: kid,
          issuerDid: didKey,
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

    group('with custom DidResolver', () {
      test('should use provided resolver instead of default', () async {
        final didDocument = DidDocument.fromJson(
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey)
              as Map<String, dynamic>,
        );

        final mockResolver = MockDidResolver(didDocument);

        final verifier = await DidVerifier.create(
          algorithm: SignatureScheme.ecdsa_secp256k1_sha256,
          kid: 'zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R',
          issuerDid: didKey,
          didResolver: mockResolver,
        );

        expect(mockResolver.resolveCalled, isTrue);
        expect(mockResolver.lastDid, equals(didKey));
        expect(verifier.isAllowedAlgorithm('ES256K'), isTrue);
      });

      test('should use custom resolver when provided', () async {
        final didDocument = DidDocument.fromJson(
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey)
              as Map<String, dynamic>,
        );

        final mockResolver = MockDidResolver(didDocument);

        await DidVerifier.create(
          algorithm: SignatureScheme.ecdsa_secp256k1_sha256,
          kid: 'zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R',
          issuerDid: didKey,
          didResolver: mockResolver,
        );

        expect(mockResolver.resolveCalled, isTrue);
        expect(mockResolver.lastDid, equals(didKey));
      });

      test('should use custom resolver with resolver address (Ivan way)',
          () async {
        // IVAN's way: When you need a custom resolver address:
        // 1. Create a UniversalDIDResolver with the address in constructor
        const customResolverAddress = 'https://example.com/resolver';
        final resolver =
            UniversalDIDResolver(resolverAddress: customResolverAddress);

        // 2. Pass that resolver instance to DidVerifier
        // This demonstrates IVAN's approach - resolver address set once in constructor
        expect(resolver.resolverAddress, equals(customResolverAddress));
      });

      test('should work without didResolver parameter (default behavior)',
          () async {
        final verifier = await DidVerifier.create(
          algorithm: SignatureScheme.ed25519,
          kid: kid,
          issuerDid: didKey,
        );

        expect(verifier.isAllowedAlgorithm('EdDSA'), isTrue);
        expect(verifier.isAllowedAlgorithm('Ed25519'), isTrue);
      });

      test('should handle exceptions from custom resolver', () async {
        final failingResolver = _FailingDidResolver();

        expect(
          () async => await DidVerifier.create(
            algorithm: SignatureScheme.ed25519,
            issuerDid: didKey,
            didResolver: failingResolver,
          ),
          throwsA(isA<SsiException>()),
        );
      });
    });

    test('should resolve both fragment and fully qualified kid', () async {
      final fragmentKid = kid;
      final fullyQualifiedKid = '$didKey#$kid';

      final verifierFragment = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: fragmentKid,
        issuerDid: didKey,
      );
      final verifierQualified = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: fullyQualifiedKid,
        issuerDid: didKey,
      );

      expect(verifierFragment.isAllowedAlgorithm('EdDSA'), isTrue);
      expect(verifierQualified.isAllowedAlgorithm('EdDSA'), isTrue);
      expect(verifierFragment.isAllowedAlgorithm('Ed25519'), isTrue);
      expect(verifierQualified.isAllowedAlgorithm('Ed25519'), isTrue);
    });
  });

  group('Algorithm Compatibility Tests', () {
    group('EdDSA Key Compatibility', () {
      test('OKP key type with Ed25519 curve should support EdDSA algorithm',
          () {
        final jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'test_key_value'};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'EdDSA'), isTrue);
      });

      test('OKP key type with Ed25519 curve should support Ed25519 algorithm',
          () {
        final jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'test_key_value'};

        expect(
            DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'Ed25519'), isTrue);
      });

      test('JWK with alg=Ed25519 should support EdDSA algorithm', () {
        final jwk = {'alg': 'Ed25519', 'x': 'test_key_value'};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'EdDSA'), isTrue);
      });

      test('JWK with alg=Ed25519 should support Ed25519 algorithm', () {
        final jwk = {'alg': 'Ed25519', 'x': 'test_key_value'};

        expect(
            DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'Ed25519'), isTrue);
      });

      test('Ed25519 key should reject incompatible algorithms', () {
        final jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'test_key_value'};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'ES256'), isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'RS256'), isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'HS256'), isFalse);
      });

      test('OKP key with non-Ed25519 curve should reject EdDSA', () {
        final jwk = {'kty': 'OKP', 'crv': 'X25519', 'x': 'test_key_value'};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'EdDSA'), isFalse);
        expect(
            DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'Ed25519'), isFalse);
      });
    });

    group('RSA Key Compatibility', () {
      test('RSA key should support RSA algorithms', () {
        // Using a minimal valid RSA JWK structure
        final jwk = {
          'kty': 'RSA',
          'n': 'AQAB', // Simple base64url value
          'e': 'AQAB'
        };

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'RS256'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'RS384'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'RS512'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'PS256'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'PS384'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'PS512'), isTrue);
      });

      test('RSA key should reject non-RSA algorithms', () {
        final jwk = {'kty': 'RSA', 'n': 'AQAB', 'e': 'AQAB'};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'ES256'), isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'EdDSA'), isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'HS256'), isFalse);
      });
    });

    group('EC Key Compatibility', () {
      test('EC key should support EC algorithms', () {
        // Using a valid secp256k1 JWK structure from the codebase
        final jwk = {
          'kty': 'EC',
          'crv': 'secp256k1',
          'x': '8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg',
          'y': '4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8'
        };

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'ES256'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'ES384'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'ES512'), isTrue);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'ES256K'), isTrue);
      });

      test('EC key should reject non-EC algorithms', () {
        final jwk = {
          'kty': 'EC',
          'crv': 'secp256k1',
          'x': '8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg',
          'y': '4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8'
        };

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'RS256'), isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'EdDSA'), isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwk, 'HS256'), isFalse);
      });
    });

    group('Error Handling', () {
      test('should handle invalid JWK structure gracefully', () {
        final invalidJwk = {'invalid': 'structure'};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(invalidJwk, 'EdDSA'),
            isFalse);
        expect(DidVerifier.isAlgorithmCompatibleWithJwk(invalidJwk, 'ES256'),
            isFalse);
      });

      test('should handle malformed JWK gracefully', () {
        final malformedJwk = {
          'kty': 'RSA',
          // Missing required fields like 'n' and 'e'
        };

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(malformedJwk, 'RS256'),
            isFalse);
      });

      test('should handle empty JWK gracefully', () {
        final emptyJwk = <String, dynamic>{};

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(emptyJwk, 'EdDSA'),
            isFalse);
      });

      test('should handle null values in JWK gracefully', () {
        final jwkWithNulls = {
          'kty': null,
          'crv': 'Ed25519',
          'x': 'test_key_value'
        };

        expect(DidVerifier.isAlgorithmCompatibleWithJwk(jwkWithNulls, 'EdDSA'),
            isFalse);
      });
    });
  });
}
