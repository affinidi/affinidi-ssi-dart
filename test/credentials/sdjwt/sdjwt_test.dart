import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';
import 'package:test/test.dart';

void main() {
  group('VcDataModelV2WithProofParser', () {
    late SdJwtDm2Suite suite = SdJwtDm2Suite();

    test("can parse", () {
      final vc = suite.parse(
          'eyJraWQiOiJFeEhrQk1XOWZtYmt2VjI2Nm1ScHVQMnNVWV9OX0VXSU4xbGFwVXpPOHJvIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE3NDA4MTUwNDMsImV4cCI6MTc0MjAyNDY0MywiX3NkX2FsZyI6InNoYS0yNTYiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaXNzdWVyIjoiaHR0cHM6Ly91bml2ZXJzaXR5LmV4YW1wbGUvaXNzdWVycy8xNCIsInZhbGlkRnJvbSI6IjIwMTAtMDEtMDFUMTk6MjM6MjRaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjp7Im5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIiwiX3NkIjpbIjBlVzU2Ri05VjNqQWpDVDFkQTRYMWV4TWlNaFc4eVYzUFFNUldoS2ZIa2ciXX0sImFsdW1uaU9mIjp7Im5hbWUiOiJFeGFtcGxlIFVuaXZlcnNpdHkifSwiX3NkIjpbImdaQk42UmVmSG1TNVhrbmVvTHl0ZkVQcjZ1M19sSWZDbTVPWi13akpxdXciXX0sImNyZWRlbnRpYWxTY2hlbWEiOlt7Il9zZCI6WyJJbDY1akg2eWd2T0pQVU9KVjVsRE9tbndwRVBtTEhxeTNrWk1VcEJmYW44IiwiSjIwdnp4bkQ0dktSaS1ENVExdGVJM21jVk1NZV9oMHdzNzBtdlFxejRQQSJdfSx7Il9zZCI6WyJfRTM3ZU12ejhqQXB0WHVVVExpcE9hQXBKNnA4aXoyenY2Mksxcl9UUzU0IiwieHdxMDVqem44RDE4cElEOHRVaGxqZzZrT25kZy1teHg3MGhoYlRkeWozayJdfV0sIl9zZCI6WyJJSVNLem1MdGpMemdpNFlwSkd1d0d2ZWpuOEpSbjlQMTZlU19XZThURFBRIiwiTk5fM2hSRFhkNzRNZ0JrUGp4eXpmT25FUWF2S2hzNUFSUGlzTXo5WnNfTSJdfQ.F980YCx02JBkUnsdUcXkInSf8qZt6WbFk35988mgcmmdy8xIP3jSoy0z68nm2r5en5sl6PQzkWzLL5P9upuEvA~WyJqTHctQzljOU9xQ2FpWXhmaXpheThRIiwgImlkIiwgImh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMzczMiJd~WyJhMElzX3NKSmw5MUk3NXJCdW55c1JnIiwgInR5cGUiLCBbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwgIkV4YW1wbGVEZWdyZWVDcmVkZW50aWFsIiwgIkV4YW1wbGVQZXJzb25DcmVkZW50aWFsIl1d~WyJ3eVlyZVRKajNVREE3VWU2dC1Ja1B3IiwgImlkIiwgImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJd~WyI2RlppNlh1b0JWdHl5aWdJekFScTZnIiwgInR5cGUiLCAiRXhhbXBsZUJhY2hlbG9yRGVncmVlIl0~WyIwSGppZ0Fnby1qT0FZZ0RIdE5ZaEt3IiwgImlkIiwgImh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZXMvZGVncmVlLmpzb24iXQ~WyJTYlNEdmdiWE5NSVhzRVJyVGdsN1dnIiwgInR5cGUiLCAiSnNvblNjaGVtYSJd~WyJPbVJvdDNIN3JIdWxPLW5wOEpIeGlBIiwgImlkIiwgImh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZXMvYWx1bW5pLmpzb24iXQ~WyJsR0xnX2p2akJybkh3NzV3bDFSSkpRIiwgInR5cGUiLCAiSnNvblNjaGVtYSJd~');
      expect(vc, isNotNull);
      expect(vc.issuer.id, equals("https://university.example/issuers/14"));
      expect(vc.credentialSchema.length, equals(2));
    });

    //todo implement this later in a different MR
    // test("can issue & verify", () {
    //   final dataModel = VcDataModelV2.fromJson(
    //     VerifiableCredentialDataFixtures.credentialWithoutProofDataModelV11,
    //   );
    //
    //   final suite = JwtDm1Suite();
    //   final jwt = await suite.issue(dataModel, signer);
    //
    //   var actualIntegrity = await suite.verifyIntegrity(jwt);
    //
    //   expect(actualIntegrity, true);
    // });

    // group('canParse', () {
    //   test('returns true for valid VC 2.0 with proof', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v2'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential', 'UniversityDegreeCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': '2010-01-01T19:23:24Z',
    //       'credentialSubject': {
    //         'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    //         'degree': {
    //           'type': 'BachelorDegree',
    //           'name': 'Bachelor of Science and Arts'
    //         }
    //       },
    //       "proof": {
    //         "type": "DataIntegrityProof",
    //         "cryptosuite": "eddsa-rdfc-2022",
    //         "created": "2021-11-13T18:19:39Z",
    //         "verificationMethod": "https://university.example/issuers/14#key-1",
    //         "proofPurpose": "assertionMethod",
    //         "proofValue": "z58DAdFfa9SkqZMVPxAQp...jQCrfFPP2oumHKtz"
    //       }
    //     };
    //
    //     expect(suite.canParse(data), isTrue);
    //   });
    //
    //   test('returns false for missing v2 context', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v1'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': '2010-01-01T19:23:24Z',
    //       'credentialSubject': {
    //         'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'
    //       },
    //       'proof': {'type': 'DataIntegrityProof'}
    //     };
    //
    //     expect(parser.canParse(data), isFalse);
    //   });
    //
    //   test('returns false for missing proof', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v2'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': '2010-01-01T19:23:24Z',
    //       'credentialSubject': {'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'}
    //     };
    //
    //     expect(parser.canParse(data), isFalse);
    //   });
    // });

    // group('parse', () {
    //   test('successfully parses valid VC 2.0 with proof', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v2'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential', 'UniversityDegreeCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': '2010-01-01T19:23:24Z',
    //       'credentialSubject': {
    //         'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    //         'degree': {
    //           'type': 'BachelorDegree',
    //           'name': 'Bachelor of Science and Arts'
    //         }
    //       },
    //       'proof': {'type': 'DataIntegrityProof'}
    //     };
    //
    //     final credential = parser.parse(data);
    //     expect(credential.id, equals('http://example.edu/credentials/3732'));
    //     expect(credential.issuer.id, equals('https://example.edu/issuers/14'));
    //     expect(credential.type,
    //         equals(['VerifiableCredential', 'UniversityDegreeCredential']));
    //     expect(credential.validFrom,
    //         equals(DateTime.parse('2010-01-01T19:23:24Z')));
    //   });
    //   test('throws when missing required properties', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v2'],
    //       'proof': {'type': 'DataIntegrityProof'}
    //     };
    //
    //     expect(
    //       () => parser.parse(data),
    //       throwsA(
    //         isA<SsiException>().having(
    //           (e) => e.code,
    //           'code',
    //           SsiExceptionType.unableToParseVerifiableCredential.code,
    //         ),
    //       ),
    //     );
    //   });
    //
    //   test('throws when context is invalid', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v1'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': '2010-01-01T19:23:24Z',
    //       'credentialSubject': {
    //         'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'
    //       },
    //       'proof': {'type': 'DataIntegrityProof'}
    //     };
    //
    //     expect(
    //       () => parser.parse(data),
    //       throwsA(
    //         isA<SsiException>().having(
    //           (e) => e.code,
    //           'code',
    //           SsiExceptionType.unableToParseVerifiableCredential.code,
    //         ),
    //       ),
    //     );
    //   });
    //
    //   test('throws when validFrom is invalid', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v2'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': 'invalid-date',
    //       'credentialSubject': {
    //         'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'
    //       },
    //       'proof': {'type': 'DataIntegrityProof'}
    //     };
    //
    //     expect(
    //       () => parser.parse(data),
    //       throwsA(
    //         isA<SsiException>().having(
    //           (e) => e.code,
    //           'code',
    //           SsiExceptionType.unableToParseVerifiableCredential.code,
    //         ),
    //       ),
    //     );
    //   });
    //
    //   test('throws when credentialSubject is invalid', () {
    //     final data = {
    //       '@context': ['https://www.w3.org/ns/credentials/v2'],
    //       'id': 'http://example.edu/credentials/3732',
    //       'type': ['VerifiableCredential'],
    //       'issuer': 'https://example.edu/issuers/14',
    //       'validFrom': '2010-01-01T19:23:24Z',
    //       'credentialSubject': 'not-an-object',
    //       'proof': {'type': 'DataIntegrityProof'}
    //     };
    //
    //     expect(
    //       () => parser.parse(data),
    //       throwsA(
    //         isA<SsiException>().having(
    //           (e) => e.code,
    //           'code',
    //           SsiExceptionType.unableToParseVerifiableCredential.code,
    //         ),
    //       ),
    //     );
    //   });
    // });
  });
}
