// ignore_for_file: avoid_print

import 'package:ssi/ssi.dart';

/// Example of using a custom DID resolver for credential verification.
///
/// This demonstrates how to provide custom DID resolution logic,
/// which is useful for:
/// - Implementing caching strategies
/// - Adding logging/monitoring
/// - Resolving custom/private DID methods
/// - Working with offline DID documents
void main() async {
  // Parse the credential
  final verifiableCredential = UniversalParser.parse(vcString);

  // Example 1: Custom DID resolver with caching
  final cachingResolver = CachingDidResolver();
  final verifierWithCache = VcIntegrityVerifier(
    didResolver: cachingResolver,
  );

  print('Verifying with caching resolver...');
  final result1 = await verifierWithCache.verify(verifiableCredential);
  print('Verification result: ${result1.isValid}');
  print('Cache hits: ${cachingResolver.cacheHits}');
  print('Cache misses: ${cachingResolver.cacheMisses}');

  // Example 2: Custom DID resolver with logging
  final loggingResolver = LoggingDidResolver();
  final verifierWithLogging = VcIntegrityVerifier(
    didResolver: loggingResolver,
  );

  print('\nVerifying with logging resolver...');
  final result2 = await verifierWithLogging.verify(verifiableCredential);
  print('Verification result: ${result2.isValid}');

  // Example 3: Using default resolver (no custom resolver)
  print('\nVerifying with default resolver...');
  final defaultVerifier = VcIntegrityVerifier();
  final result3 = await defaultVerifier.verify(verifiableCredential);
  print('Verification result: ${result3.isValid}');
}

/// Example custom DID resolver with caching functionality.
///
/// Caches resolved DID documents to avoid redundant network calls.
class CachingDidResolver implements DidResolver {
  final Map<String, DidDocument> _cache = {};
  final DidResolver _fallbackResolver = UniversalDIDResolver();

  int cacheHits = 0;
  int cacheMisses = 0;

  @override
  Future<DidDocument> resolveDid(String did) async {
    // Check cache first
    if (_cache.containsKey(did)) {
      cacheHits++;
      print('Cache HIT for $did');
      return _cache[did]!;
    }

    // Cache miss - resolve and cache
    cacheMisses++;
    print('Cache MISS for $did - resolving...');
    final document = await _fallbackResolver.resolveDid(did);
    _cache[did] = document;
    return document;
  }
}

/// Example custom DID resolver with logging functionality.
///
/// Logs all DID resolution requests for monitoring and debugging.
class LoggingDidResolver implements DidResolver {
  final DidResolver _fallbackResolver = UniversalDIDResolver();
  final List<String> resolvedDids = [];

  @override
  Future<DidDocument> resolveDid(String did) async {
    print('Resolving DID: $did');
    resolvedDids.add(did);

    try {
      final document = await _fallbackResolver.resolveDid(did);
      print('Successfully resolved $did');
      return document;
    } catch (e) {
      print('Failed to resolve $did: $e');
      rethrow;
    }
  }
}

// Example VC string with did:key issuer
const vcString = r'''
  {
      "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld"
      ],
      "id": "uuid:123456abcd",
      "type": [
          "VerifiableCredential",
          "UserProfile"
      ],
      "credentialSubject": {
          "Fname": "Fname",
          "Lname": "Lame",
          "Age": "22",
          "Address": "Eihhornstr"
      },
      "credentialSchema": {
          "id": "https://schema.affinidi.com/UserProfileV1-0.json",
          "type": "JsonSchemaValidator2018"
      },
      "issuanceDate": "2023-01-01T09:51:00.272Z",
      "expirationDate": "3024-01-01T12:00:00Z",
      "issuer": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2025-04-11T15:20:35Z",
          "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jL90Nk1rSfgBXgZJif44x1KkdD0iYgkRjTfChEb0W0gJ6HDDc5BVE5jb1osse7JEueSSJcYaAMfbh_2QsOdcSA"
      }
  }
  ''';
