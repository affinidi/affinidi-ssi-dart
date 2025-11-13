import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SD-JWT Parser Tests', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    test('canParse returns false for non-string input', () {
      expect(suite.canParse(123), isFalse);
      expect(suite.canParse({'key': 'value'}), isFalse);
      expect(suite.canParse([1, 2, 3]), isFalse);
    });

    test('canParse returns false for invalid SD-JWT string', () {
      expect(suite.canParse('invalid.jwt.string'), isFalse);
      expect(suite.canParse('not-a-jwt'), isFalse);
      expect(suite.canParse(''), isFalse);
    });

    test('canParse returns true for valid SD-JWT string', () async {
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: DateTime.now().subtract(Duration(hours: 1)),
        validUntil: DateTime.now().add(Duration(hours: 24)),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);
      final validSdJwt = issuedCredential.serialized;

      expect(suite.canParse(validSdJwt), isTrue);
    });

    test('parse throws exception for non-string input', () {
      expect(
        () => suite.parse(123),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          'Only String is supported',
        )),
      );
    });

    test('tryParse returns null for invalid input', () {
      expect(suite.tryParse(123), isNull);
      expect(suite.tryParse('invalid-jwt'), isNull);
    });

    test('tryParse returns credential for valid input', () async {
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: DateTime.now().subtract(Duration(hours: 1)),
        validUntil: DateTime.now().add(Duration(hours: 24)),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);
      final validSdJwt = issuedCredential.serialized;

      final result = suite.tryParse(validSdJwt);
      expect(result, isNotNull);
      expect(result, isA<SdJwtDataModelV2>());
    });

    test('parsed credential has expected properties', () async {
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: DateTime.now().subtract(Duration(hours: 1)),
        validUntil: DateTime.now().add(Duration(hours: 24)),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);
      final validSdJwt = issuedCredential.serialized;
      
      final parsedCredential = suite.parse(validSdJwt);
      
      expect(parsedCredential.serialized, equals(validSdJwt));
      expect(parsedCredential.header, isNotEmpty);
      expect(parsedCredential.header, contains('alg'));
      expect(parsedCredential.disclosures, isNotEmpty);
      expect(parsedCredential.issuer.id.toString(), equals(signer.did));
    });
  });
}