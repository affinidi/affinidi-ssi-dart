import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SD-JWT VC Data Model V2 - Header JWK Validation', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    test(
        'verifyIntegrity should succeed when SD-JWT has no jwk field in header (existing behavior)',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Verify the credential - should pass since no jwk in header
      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test(
        'verifyIntegrity should succeed when SD-JWT has matching jwk in header',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-with-jwk',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Get the DID document to extract the public key JWK
      final didDoc = DidKey.resolve(signer.did);
      final verificationMethod = didDoc.verificationMethod.first;
      final publicKeyJwk = verificationMethod.asJwk().toJson();

      // Manually add the correct jwk to the header and re-sign
      final sdJwtWithJwk = await _createSdJwtWithJwkHeader(
          issuedCredential.serialized,
          Map<String, dynamic>.from(publicKeyJwk),
          signer);

      final parsedCredential = UniversalParser.parse(sdJwtWithJwk);

      // Verify the credential - should pass with matching jwk
      final isValid =
          await suite.verifyIntegrity(parsedCredential as SdJwtDataModelV2);
      expect(isValid, isTrue);
    });

    test(
        'verifyIntegrity should fail when SD-JWT has mismatched jwk in header (different key)',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-mismatched-jwk',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Create a different key to simulate a mismatched jwk
      final differentSeed =
          Uint8List.fromList(List.generate(32, (index) => index + 100));
      final differentSigner = await initSigner(differentSeed);
      final differentDidDoc = DidKey.resolve(differentSigner.did);
      final differentJwk =
          differentDidDoc.verificationMethod.first.asJwk().toJson();

      // Add the mismatched jwk to the header and re-sign with original signer
      final sdJwtWithMismatchedJwk = await _createSdJwtWithJwkHeader(
          issuedCredential.serialized,
          Map<String, dynamic>.from(differentJwk),
          signer);

      final parsedCredential = UniversalParser.parse(sdJwtWithMismatchedJwk);

      // Verify should throw an exception due to mismatched jwk
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as SdJwtDataModelV2),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });

    test(
        'verifyIntegrity should fail when SD-JWT has malformed jwk in header (missing required fields)',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-malformed-jwk',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Create a malformed jwk (missing required fields)
      final malformedJwk = {
        'kty': 'EC',
        // Missing crv, x, y fields
      };

      // Add the malformed jwk to the header and re-sign
      final sdJwtWithMalformedJwk = await _createSdJwtWithJwkHeader(
          issuedCredential.serialized, malformedJwk, signer);

      final parsedCredential = UniversalParser.parse(sdJwtWithMalformedJwk);

      // Verify should throw an exception due to malformed jwk
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as SdJwtDataModelV2),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });

    test(
        'verifyIntegrity should fail when SD-JWT has jwk with different curve than DID document',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-different-curve',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Create a P-256 signer (different curve from secp256k1)
      final p256Signer = await initP256Signer(testSeed);
      final p256DidDoc = DidKey.resolve(p256Signer.did);
      final p256Jwk = p256DidDoc.verificationMethod.first.asJwk().toJson();

      // Add the P-256 jwk to a secp256k1 SD-JWT and re-sign
      final sdJwtWithDifferentCurve = await _createSdJwtWithJwkHeader(
          issuedCredential.serialized,
          Map<String, dynamic>.from(p256Jwk),
          signer);

      final parsedCredential = UniversalParser.parse(sdJwtWithDifferentCurve);

      // Verify should throw an exception due to different curve
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as SdJwtDataModelV2),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });

    test(
        'verifyIntegrity should fail when SD-JWT has jwk with modified coordinates',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-metadata-diff',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Get the correct JWK
      final didDoc = DidKey.resolve(signer.did);
      final verificationMethod = didDoc.verificationMethod.first;
      final correctJwk =
          Map<String, dynamic>.from(verificationMethod.asJwk().toJson());

      // Modify only the x coordinate to make it invalid
      final invalidJwk = Map<String, dynamic>.from(correctJwk);
      // Change just one character in the base64url encoded x value
      final originalX = invalidJwk['x'] as String;
      invalidJwk['x'] = originalX.substring(0, originalX.length - 1) +
          (originalX.endsWith('A') ? 'B' : 'A');

      // Add the jwk with modified x coordinate and re-sign
      final sdJwtWithModifiedJwk = await _createSdJwtWithJwkHeader(
          issuedCredential.serialized, invalidJwk, signer);

      final parsedCredential = UniversalParser.parse(sdJwtWithModifiedJwk);

      // Verify should fail because coordinates don't match
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as SdJwtDataModelV2),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });
  });
}

/// Helper function to add a jwk field to an SD-JWT header and re-sign it.
///
/// This creates a modified SD-JWT with a jwk field in the header that is properly
/// signed, allowing us to test the jwk validation logic independently.
///
/// Note: This function only modifies the JWT portion, not the disclosures.
Future<String> _createSdJwtWithJwkHeader(
    String sdJwt, Map<String, dynamic> jwk, DidSigner signer) async {
  // Split SD-JWT into JWT and disclosures
  final parts = sdJwt.split('~');
  final jwt = parts[0];
  final disclosures = parts.sublist(1);

  // Modify the JWT header
  final jwtParts = jwt.split('.');
  if (jwtParts.length != 3) {
    throw ArgumentError('Invalid JWT format');
  }

  // Decode the header and add the jwk field
  final headerBytes = base64Url.decode(base64Url.normalize(jwtParts[0]));
  final header = jsonDecode(utf8.decode(headerBytes)) as Map<String, dynamic>;
  header['jwk'] = jwk;

  // Re-encode the header
  final modifiedHeaderBytes = utf8.encode(jsonEncode(header));
  final encodedHeader =
      base64Url.encode(modifiedHeaderBytes).replaceAll('=', '');

  // Keep the original payload
  final encodedPayload = jwtParts[1];

  // Re-sign with the modified header
  final toSign = ascii.encode('$encodedHeader.$encodedPayload');
  final signature = await signer.sign(toSign);
  final encodedSignature = base64Url.encode(signature).replaceAll('=', '');

  final modifiedJwt = '$encodedHeader.$encodedPayload.$encodedSignature';

  // Reconstruct SD-JWT with original disclosures
  return [modifiedJwt, ...disclosures].join('~');
}
