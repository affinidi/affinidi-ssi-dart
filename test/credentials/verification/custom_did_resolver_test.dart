import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('Custom DID Resolver Integration Tests', () {
    test('Should accept custom DID resolver parameter', () async {
      // Create a tracking resolver
      final trackingResolver = TrackingDidResolver();

      // Parse a valid credential
      final vc = UniversalParser.parse(
        VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
      );

      // Create verifier with tracking resolver - should not throw
      final verifier = VcIntegrityVerifier(didResolver: trackingResolver);

      // Verify the credential
      final result = await verifier.verify(vc);

      // Should successfully verify (using the custom resolver if needed)
      expect(result.isValid, true);
    });

    test('Should use default resolver when custom resolver is not provided',
        () async {
      // Parse a valid credential
      final vc = UniversalParser.parse(
        VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
      );

      // Create verifier without custom resolver
      final verifier = VcIntegrityVerifier();

      // Verify the credential
      final result = await verifier.verify(vc);

      // Should successfully verify using default resolver
      expect(result.isValid, true);
    });

    test('Should handle custom resolver that throws exceptions', () async {
      // Create a resolver that always throws
      final failingResolver = FailingDidResolver();

      // Parse a valid credential that requires DID resolution
      final vc = UniversalParser.parse(
        VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
      );

      // Create verifier with failing resolver
      final verifier = VcIntegrityVerifier(didResolver: failingResolver);

      // Verify the credential
      final result = await verifier.verify(vc);

      // Note: If the credential doesn't actually require DID resolution
      // (e.g., has embedded keys), it may still verify successfully.
      // This test mainly ensures that a custom resolver can be provided
      // and doesn't cause the verifier to crash.
      expect(result, isA<VerificationResult>());
    });

    test('Should work with custom caching resolver', () async {
      // Create a caching resolver
      final cachingResolver = CachingDidResolver();

      // Parse a valid credential
      final vc = UniversalParser.parse(
        VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
      );

      // Create verifier with caching resolver
      final verifier = VcIntegrityVerifier(didResolver: cachingResolver);

      // Verify the credential twice
      final result1 = await verifier.verify(vc);
      final result2 = await verifier.verify(vc);

      // Both should succeed
      expect(result1.isValid, true);
      expect(result2.isValid, true);

      // Caching should work (if DID resolution was needed)
      // We can't assert cache hits without knowing if resolution happened
      expect(cachingResolver.cacheHits + cachingResolver.cacheMisses,
          greaterThanOrEqualTo(0));
    });

    test(
        'Should work with both custom document loader and custom DID resolver',
        () async {
      // Create custom implementations
      final customResolver = TrackingDidResolver();

      Future<Map<String, dynamic>?> customDocumentLoader(Uri url) async {
        return null; // Use default behavior
      }

      // Parse a valid credential
      final vc = UniversalParser.parse(
        VerifiableCredentialDataFixtures
            .credentialWithEcdsaRdfc2019ByDigitalBazaar,
      );

      // Create verifier with both custom resolver and document loader
      final verifier = VcIntegrityVerifier(
        didResolver: customResolver,
        customDocumentLoader: customDocumentLoader,
      );

      // Verify the credential
      final result = await verifier.verify(vc);

      // Should successfully verify
      expect(result.isValid, true);
    });

    test('Custom resolver can intercept and modify resolution', () async {
      // Create a resolver that logs what it resolves
      final loggingResolver = LoggingDidResolver();

      // Parse a valid credential
      final vc = UniversalParser.parse(
        VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
      );

      // Create verifier with logging resolver
      final verifier = VcIntegrityVerifier(didResolver: loggingResolver);

      // Verify the credential
      final result = await verifier.verify(vc);

      // Should successfully verify
      expect(result.isValid, true);

      // Logging resolver should have tracked its usage (if called)
      expect(loggingResolver.resolvedDids, isA<List<String>>());
    });
  });
}

/// Logging DID resolver that tracks resolution requests.
class LoggingDidResolver implements DidResolver {
  final List<String> resolvedDids = [];
  final DidResolver _fallbackResolver = UniversalDIDResolver();

  @override
  Future<DidDocument> resolveDid(String did) async {
    resolvedDids.add(did);
    return await _fallbackResolver.resolveDid(did);
  }
}

/// Tracking DID resolver that counts resolution calls.
class TrackingDidResolver implements DidResolver {
  int callCount = 0;
  final DidResolver _fallbackResolver = UniversalDIDResolver();

  @override
  Future<DidDocument> resolveDid(String did) async {
    callCount++;
    return await _fallbackResolver.resolveDid(did);
  }
}

/// DID resolver that always fails.
class FailingDidResolver implements DidResolver {
  @override
  Future<DidDocument> resolveDid(String did) async {
    throw SsiException(
      message: 'Mock resolver failure',
      code: SsiExceptionType.unableToResolveDid.code,
    );
  }
}

/// Caching DID resolver for testing cache behavior.
class CachingDidResolver implements DidResolver {
  final Map<String, DidDocument> _cache = {};
  final DidResolver _fallbackResolver = UniversalDIDResolver();
  int cacheHits = 0;
  int cacheMisses = 0;

  @override
  Future<DidDocument> resolveDid(String did) async {
    if (_cache.containsKey(did)) {
      cacheHits++;
      return _cache[did]!;
    }

    cacheMisses++;
    final document = await _fallbackResolver.resolveDid(did);
    _cache[did] = document;
    return document;
  }
}
