import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/jwt/jwt_dm_v1_suite.dart';
import 'package:ssi/src/credentials/models/v1/mutable_vc_data_model_v1.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import 'fixtures/verifiable_credentials_data_fixtures.dart';
import 'test_utils.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  late final DidSigner signer;

  setUpAll(() async {
    signer = await initSigner(seed);
  });

  group('When parsing verifiable credentials with a data model v1.1', () {
    group('and receiving a json structure', () {
      group('with a proof', () {
        var data =
            VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;

        final verifiableCredential = UniversalParser.parse(
          VerifiableCredentialDataFixtures
              .credentialWithProofDataModelV11JsonEncoded,
        );

        test(
          'it retrieves the correct issuer',
          () async {
            expect(verifiableCredential.issuer.id,
                'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa');
          },
        );

        test(
          'it retrieves the correct type',
          () {
            expect(verifiableCredential.type,
                ['VerifiableCredential', 'HITContacts']);
          },
        );

        test(
          'it retrieves the correct issuance date',
          () {
            expect(verifiableCredential.validFrom,
                DateTime(2024, 07, 16, 20, 16, 05, 648));
          },
        );

        test(
          'it retrieves the correct credentials subject',
          () {
            expect(verifiableCredential.credentialSubject['email'],
                'user@affinidi.com');
          },
        );

        test(
          'it retrieves the correct id',
          () {
            expect(verifiableCredential.id, 'claimId:02-aaaaaa-aaaaaaaaaaa');
          },
        );

        test(
          'it retrieves the correct schema',
          () {
            expect(verifiableCredential.credentialSchema.firstOrNull?.id,
                'credentialSchemaId');
            expect(verifiableCredential.credentialSchema.firstOrNull?.type,
                'credentialSchemaType');
          },
        );

        test(
          'it retrieves the correct valid until date',
          () {
            expect(verifiableCredential.validUntil,
                DateTime(2024, 07, 18, 20, 16, 05, 648));
          },
        );

        test(
          'it holds the original json data provided to create the instance',
          () {
            final expected = Map<String, dynamic>.from(
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV11);
            if (expected['issuer'] is Map &&
                expected['issuer'].length == 1 &&
                expected['issuer']['id'] != null) {
              expected['issuer'] = expected['issuer']['id'];
            }
            expect(verifiableCredential.toJson(), expected);
          },
        );

        test(
          'it holds the original raw data provided to create the instance',
          () {
            expect(
                verifiableCredential.serialized,
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV11JsonEncoded);
          },
        );

        group('and amending the initial input data identifier', () {
          data['id'] = 'modified';

          test(
            'it does not update the verifiable credential identifier',
            () {
              expect(
                  verifiableCredential.id,
                  VerifiableCredentialDataFixtures
                      .credentialWithProofDataModelV11['id']);
            },
          );
        });
      });

      group('without a proof', () {
        test(
          'it throws an unknown format exception',
          () {
            expect(
                () => UniversalParser.parse(VerifiableCredentialDataFixtures
                    .credentialWithoutProofDataModelV11),
                throwsA(isA<SsiException>().having(
                    (error) => error.code,
                    'code',
                    SsiExceptionType.unableToParseVerifiableCredential.code)));
          },
        );
      });
    });

    group('and receiving a JWT token', () {
      var data = VerifiableCredentialDataFixtures.jwtCredentialDataModelV11;
      final verifiableCredential = UniversalParser.parse(data);

      test(
        'it has correct signature',
        () async {
          expect(
              await JwtDm1Suite()
                  .verifyIntegrity(verifiableCredential as JwtVcDataModelV1),
              true);
        },
      );

      test(
        'it has invalid signature',
        () async {
          final verifiableCredential = UniversalParser.parse(
              VerifiableCredentialDataFixtures
                  .jwtCredentialDataModelV11InvalidSig);

          var actualIntegrity = await JwtDm1Suite()
              .verifyIntegrity(verifiableCredential as JwtVcDataModelV1);

          expect(actualIntegrity, false);
        },
      );

      test(
        'it can encode & decode',
        () async {
          final dataModel = MutableVcDataModelV1.fromJson(
            VerifiableCredentialDataFixtures.credentialWithoutProofDataModelV11,
          );

          final suite = JwtDm1Suite();
          final jwt = await suite.issue(dataModel, signer);

          var actualIntegrity = await suite.verifyIntegrity(jwt);

          expect(actualIntegrity, true);
        },
      );

      test(
        'it retrieves the correct issuer',
        () {
          expect(verifiableCredential.issuer.id,
              'https://example.edu/issuers/565049');
        },
      );

      test(
        'it retrieves the correct credential type',
        () {
          expect(verifiableCredential.type,
              ['VerifiableCredential', 'UniversityDegreeCredential']);
        },
      );

      test(
        'it retrieves the correct issuance date',
        () {
          expect(verifiableCredential.validFrom,
              DateTime.utc(2010, 01, 01, 00, 00, 00));
        },
      );

      test(
        'it retrieves the correct credential subject with a profession position',
        () {
          expect(verifiableCredential.credentialSubject.id,
              'did:example:ebfeb1f712ebc6f1c276e12ec21');
        },
      );

      test(
        'it retrieves the correct id',
        () {
          expect(
              verifiableCredential.id, 'http://example.edu/credentials/3732');
        },
      );

      test(
        'it retrieves the correct schema',
        () {
          expect(verifiableCredential.credentialSchema, isEmpty);
        },
      );

      test(
        'it does not have an expiry date',
        () {
          expect(verifiableCredential.validUntil, isNull);
        },
      );

      test(
        'it holds the original json data provided to create the instance',
        () {
          final expected = Map<String, dynamic>.from(
              VerifiableCredentialDataFixtures
                  .jwtCredentialDataModelV11Decoded);
          if (expected['issuer'] is Map &&
              expected['issuer'].length == 1 &&
              expected['issuer']['id'] != null) {
            expected['issuer'] = expected['issuer']['id'];
          }
          final actual =
              Map<String, dynamic>.from(verifiableCredential.toJson());
          // Remove 'proof' if not present in expected
          if (!expected.containsKey('proof')) {
            actual.remove('proof');
          }
          expect(actual, expected);
        },
      );

      test(
        'it holds the original raw data provided to create the instance',
        () {
          expect(verifiableCredential.serialized,
              VerifiableCredentialDataFixtures.jwtCredentialDataModelV11);
        },
      );

      test(
        'it passes integrity check',
        () async {
          var actualIntegrity = await JwtDm1Suite()
              .verifyIntegrity(verifiableCredential as JwtVcDataModelV1);
          expect(actualIntegrity, true);
        },
      );

      group('and amending the initial data', () {
        data = 'aaa';

        test('it does not update the verifiable credential rawData', () {
          expect(verifiableCredential.serialized,
              VerifiableCredentialDataFixtures.jwtCredentialDataModelV11);
        });
      });
    });
  });

  group('When parsing verifiable credentials with a data model v2', () {
    group('and receiving a json structure', () {
      group('with a proof', () {
        var data = VerifiableCredentialDataFixtures
            .credentialWithProofDataModelV20String;
        final verifiableCredential = UniversalParser.parse(data);
        test(
          'it retrieves the correct issuer',
          () {
            expect(verifiableCredential.issuer.id,
                'did:example:6fb1f712ebe12c27cc26eebfe11');
          },
        );

        test(
          'it retrieves the correct type',
          () {
            expect(verifiableCredential.type,
                ['VerifiableCredential', 'ExampleDegreeCredential']);
          },
        );

        test(
          'it retrieves the correct issuance date',
          () {
            expect(verifiableCredential.validFrom,
                DateTime.utc(2010, 01, 01, 19, 23, 24, 0));
          },
        );

        test(
          'it retrieves the correct credentials subject',
          () {
            expect(verifiableCredential.credentialSubject.id,
                'https://subject.example/subject/3921');
          },
        );

        test(
          'it retrieves the correct id',
          () {
            expect(verifiableCredential.id,
                'https://example.gov/credentials/3732');
          },
        );

        test(
          'it retrieves the correct schema',
          () {
            expect(verifiableCredential.credentialSchema.firstOrNull?.id,
                'https://example.org/examples/degree.json');
            expect(verifiableCredential.credentialSchema.firstOrNull?.type,
                'JsonSchema');
            expect(verifiableCredential.credentialSchema.lastOrNull?.id,
                'https://example.org/examples/alumni.json');
            expect(verifiableCredential.credentialSchema.lastOrNull?.type,
                'JsonSchema');
          },
        );

        test(
          'it retrieves the correct valid until date',
          () {
            expect(verifiableCredential.validUntil,
                DateTime.utc(2020, 02, 01, 19, 25, 24, 0));
          },
        );

        test(
          'it holds the original json data provided to create the instance',
          () {
            final expected = Map<String, dynamic>.from(
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV20);
            if (expected['issuer'] is Map &&
                expected['issuer'].length == 1 &&
                expected['issuer']['id'] != null) {
              expected['issuer'] = expected['issuer']['id'];
            }
            final actual =
                Map<String, dynamic>.from(verifiableCredential.toJson());
            // Normalize 'created' field in proof if present
            if (expected['proof'] != null && actual['proof'] != null) {
              final expProof = Map<String, dynamic>.from(expected['proof']);
              final actProof = Map<String, dynamic>.from(actual['proof']);
              if (expProof['created'] != null && actProof['created'] != null) {
                // Remove milliseconds if present in actual
                actProof['created'] =
                    actProof['created'].replaceAll('.000Z', 'Z');
                expected['proof'] = expProof;
                actual['proof'] = actProof;
              }
            }
            expect(actual, expected);
          },
        );

        test(
          'it holds the original raw data provided to create the instance',
          () {
            expect(
                verifiableCredential.serialized,
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV20String);
          },
        );
      });

      group('without a proof', () {
        test(
          'it throws an unknown format exception',
          () {
            expect(
                () => UniversalParser.parse(VerifiableCredentialDataFixtures
                    .credentialWithoutProofDataModelV20),
                throwsA(isA<SsiException>().having(
                    (error) => error.code,
                    'code',
                    SsiExceptionType.unableToParseVerifiableCredential.code)));
          },
        );
      });
    });
  });
}
