import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('JWT VC Data Model V1 - Header JWK Validation', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late JwtDm1Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = JwtDm1Suite();
    });

    test('verifyIntegrity should succeed when JWT has matching jwk in header',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-with-jwk',
        'type': ['VerifiableCredential', 'TestCredential'],
        'holder': {'id': signer.did},
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Get the DID document to extract the public key JWK
      final didDoc = DidKey.resolve(signer.did);
      final verificationMethod = didDoc.verificationMethod.first;
      final publicKeyJwk = verificationMethod.asJwk().toJson();

      // Manually add the correct jwk to the header and re-sign
      final jwtWithJwk = await _createJwtWithJwkHeader(
          issuedCredential.serialized,
          Map<String, dynamic>.from(publicKeyJwk),
          signer);

      final parsedCredential = UniversalParser.parse(jwtWithJwk);

      // Verify the credential - should pass with matching jwk
      final isValid =
          await suite.verifyIntegrity(parsedCredential as JwtVcDataModelV1);
      expect(isValid, isTrue);
    });

    test(
        'verifyIntegrity should fail when JWT has mismatched jwk in header (different key)',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-mismatched-jwk',
        'type': ['VerifiableCredential', 'TestCredential'],
        'holder': {'id': signer.did},
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Create a different key to simulate a mismatched jwk
      final differentSeed =
          Uint8List.fromList(List.generate(32, (index) => index + 100));
      final differentSigner = await initSigner(differentSeed);
      final differentDidDoc = DidKey.resolve(differentSigner.did);
      final differentJwk =
          differentDidDoc.verificationMethod.first.asJwk().toJson();

      // Add the mismatched jwk to the header and re-sign with original signer
      final jwtWithMismatchedJwk = await _createJwtWithJwkHeader(
          issuedCredential.serialized,
          Map<String, dynamic>.from(differentJwk),
          signer);

      final parsedCredential = UniversalParser.parse(jwtWithMismatchedJwk);

      // Verify should throw an exception due to mismatched jwk
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as JwtVcDataModelV1),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });

    test(
        'verifyIntegrity should fail when JWT has malformed jwk in header (missing required fields)',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-malformed-jwk',
        'type': ['VerifiableCredential', 'TestCredential'],
        'holder': {'id': signer.did},
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Create a malformed jwk (missing required fields)
      final malformedJwk = {
        'kty': 'EC',
        // Missing crv, x, y fields
      };

      // Add the malformed jwk to the header and re-sign
      final jwtWithMalformedJwk = await _createJwtWithJwkHeader(
          issuedCredential.serialized, malformedJwk, signer);

      final parsedCredential = UniversalParser.parse(jwtWithMalformedJwk);

      // Verify should throw an exception due to malformed jwk
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as JwtVcDataModelV1),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });

    test(
        'verifyIntegrity should fail when JWT has jwk with different curve than DID document',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-different-curve',
        'type': ['VerifiableCredential', 'TestCredential'],
        'holder': {'id': signer.did},
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Create a P-256 signer (different curve from secp256k1)
      final p256Signer = await initP256Signer(testSeed);
      final p256DidDoc = DidKey.resolve(p256Signer.did);
      final p256Jwk = p256DidDoc.verificationMethod.first.asJwk().toJson();

      // Add the P-256 jwk to a secp256k1 JWT and re-sign
      final jwtWithDifferentCurve = await _createJwtWithJwkHeader(
          issuedCredential.serialized,
          Map<String, dynamic>.from(p256Jwk),
          signer);

      final parsedCredential = UniversalParser.parse(jwtWithDifferentCurve);

      // Verify should throw an exception due to different curve
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as JwtVcDataModelV1),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });

    test(
        'verifyIntegrity should fail when JWT has jwk with correct coordinates but extra/different metadata',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-metadata-diff',
        'type': ['VerifiableCredential', 'TestCredential'],
        'holder': {'id': signer.did},
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })
        ..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

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
      final jwtWithModifiedJwk = await _createJwtWithJwkHeader(
          issuedCredential.serialized, invalidJwk, signer);

      final parsedCredential = UniversalParser.parse(jwtWithModifiedJwk);

      // Verify should fail because coordinates don't match
      expect(
          () async =>
              await suite.verifyIntegrity(parsedCredential as JwtVcDataModelV1),
          throwsA(isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains(
                  'Header JWK does not match the public key from DID document'))));
    });
  });
}

/// Helper function to add a jwk field to a JWT header and re-sign it.
///
/// This creates a modified JWT with a jwk field in the header that is properly
/// signed, allowing us to test the jwk validation logic independently.
Future<String> _createJwtWithJwkHeader(
    String jwt, Map<String, dynamic> jwk, DidSigner signer) async {
  final parts = jwt.split('.');
  if (parts.length != 3) {
    throw ArgumentError('Invalid JWT format');
  }

  // Decode the header and add the jwk field
  final headerBytes = base64Url.decode(base64Url.normalize(parts[0]));
  final header = jsonDecode(utf8.decode(headerBytes)) as Map<String, dynamic>;
  header['jwk'] = jwk;

  // Re-encode the header
  final modifiedHeaderBytes = utf8.encode(jsonEncode(header));
  final encodedHeader =
      base64Url.encode(modifiedHeaderBytes).replaceAll('=', '');

  // Keep the original payload
  final encodedPayload = parts[1];

  // Re-sign with the modified header
  final toSign = ascii.encode('$encodedHeader.$encodedPayload');
  final signature = await signer.sign(toSign);
  final encodedSignature = base64Url.encode(signature).replaceAll('=', '');

  return '$encodedHeader.$encodedPayload.$encodedSignature';
}
