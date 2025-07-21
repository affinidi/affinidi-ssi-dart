import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/did/did_resolver.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

class MockDidResolver implements DidResolver {
  final DidDocument mockDocument;
  bool resolveCalled = false;
  String? lastDid;
  String? lastResolverAddress;

  MockDidResolver(this.mockDocument);

  @override
  Future<DidDocument> resolve(
    String did, {
    String? resolverAddress,
  }) async {
    resolveCalled = true;
    lastDid = did;
    lastResolverAddress = resolverAddress;
    return mockDocument;
  }
}

class _FailingDidResolver implements DidResolver {
  @override
  Future<DidDocument> resolve(
    String did, {
    String? resolverAddress,
  }) async {
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

      test('should pass resolverAddress to custom resolver', () async {
        const customResolverAddress = 'https://example.com/resolver';
        final didDocument = DidDocument.fromJson(
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey)
              as Map<String, dynamic>,
        );

        final mockResolver = MockDidResolver(didDocument);

        await DidVerifier.create(
          algorithm: SignatureScheme.ecdsa_secp256k1_sha256,
          kid: 'zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R',
          issuerDid: didKey,
          resolverAddress: customResolverAddress,
          didResolver: mockResolver,
        );

        expect(mockResolver.resolveCalled, isTrue);
        expect(mockResolver.lastDid, equals(didKey));
        expect(mockResolver.lastResolverAddress, equals(customResolverAddress));
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
  });
}
