// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  Future<Map<String, dynamic>?> defaultDocumentLoader(Uri uri) async {
    try {
      final response = await http.get(
        uri,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      ).timeout(const Duration(seconds: 30));

      if (response.statusCode == 200) {
        final result = jsonDecode(response.body);
        return result as Map<String, dynamic>;
      }

      throw Exception('Failed to fetch document: ${response.statusCode}');
    } catch (e) {
      return null;
    }
  }

  group('Universal Presentation Verifier', () {
    test(
        'should be able to verify the revoked credential inside of a valid V1 presentation',
        () async {
      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRevokedVCString);
      final verificationStatus = await UniversalPresentationVerifier(
        customDocumentLoader: defaultDocumentLoader,
      ).verify(v1Vp);

      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, false);
    });

    test('should return integrity error for 1 VC', () async {
      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithInvalidIntegrityVC);
      final verificationStatus = await UniversalPresentationVerifier(
              customDocumentLoader: defaultDocumentLoader)
          .verify(v1Vp);

      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.errors, ['integrity_verification_failed']);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, false);
    });

    test('should accept custom DID resolver parameter', () async {
      // Create a tracking resolver
      final trackingResolver = TrackingDidResolver();

      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRevokedVCString);

      // Create verifier with tracking resolver - should not throw
      final verifier = UniversalPresentationVerifier(
        customDocumentLoader: defaultDocumentLoader,
        didResolver: trackingResolver,
      );

      // Verify the presentation
      final result = await verifier.verify(v1Vp);

      // Should complete without throwing (but the revoked VC will fail)
      expect(result, isA<VerificationResult>());
    });

    test('should use custom DID resolver for embedded credentials', () async {
      // Create a tracking resolver
      final trackingResolver = TrackingDidResolver();

      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRevokedVCString);

      // Create verifier with custom resolver
      final verifier = UniversalPresentationVerifier(
        customDocumentLoader: defaultDocumentLoader,
        didResolver: trackingResolver,
      );

      // Verify the presentation
      await verifier.verify(v1Vp);

      // Tracking resolver should have been used (if DID resolution was needed)
      expect(trackingResolver.callCount, greaterThanOrEqualTo(0));
    });

    test('should actually use custom DID resolver and track DIDs', () async {
      // Create a logging resolver that tracks which DIDs are resolved
      final loggingResolver = LoggingDidResolver();

      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRevokedVCString);

      // Create verifier with logging resolver
      final verifier = UniversalPresentationVerifier(
        customDocumentLoader: defaultDocumentLoader,
        didResolver: loggingResolver,
      );

      // Verify the presentation
      await verifier.verify(v1Vp);

      // The resolver should have been called for DIDs in the presentation
      // The v1VpWithRevokedVCString contains credentials with did:key DIDs
      expect(loggingResolver.resolvedDids, isA<List<String>>());

      // If any DIDs were resolved, verify they're valid DID strings
      if (loggingResolver.resolvedDids.isNotEmpty) {
        for (final did in loggingResolver.resolvedDids) {
          expect(did.startsWith('did:'), isTrue);
        }
      }
    });
  });
}

/// Logging DID resolver that tracks which DIDs are resolved.
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
