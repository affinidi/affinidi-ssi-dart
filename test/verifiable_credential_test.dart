import 'package:ssi/src/credentials/verifier/jwt_vc_data_model_v1_verifier.dart';
import 'package:ssi/src/credentials/verifier/vc_data_model_v1_verifier.dart';
import 'package:ssi/src/credentials/verifier/vc_data_model_v2_verifier.dart';
import 'package:ssi/ssi.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:test/test.dart';

import 'fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('When parsing verifiable credentials with a data model v1.1', () {
    group('and receiving a json structure', () {
      group('with a proof', () {
        var data =
            VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
        final verifiableCredential = VerifiableCredentialFactory.create(data);
        final vcDataModelVerifier = VcDataModelV1Verifier();
        test(
          'it retrieves the correct issuer',
          () {
            expect(verifiableCredential.issuer,
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
          'it should return false for verifyExpiry',
          () async {
            expect(await vcDataModelVerifier.verifyExpiry(verifiableCredential),
                false);
          },
        );

        test(
          'it holds the original json data provided to create the instance',
          () {
            expect(
                verifiableCredential.toJson(),
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV11);
          },
        );

        test(
          'it holds the original raw data provided to create the instance',
          () {
            expect(
                verifiableCredential.rawData,
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV11);
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
                () => VerifiableCredentialFactory.create(
                    VerifiableCredentialDataFixtures
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
      final verifiableCredential = VerifiableCredentialFactory.create(data);
      final vcDataModelVerifier = JwtVcDataModelV1Verifier();

      test(
        'it retrieves the correct issuer',
        () {
          expect(verifiableCredential.issuer, 'Issuer C');
        },
      );

      test(
        'it retrieves the correct credential type',
        () {
          expect(verifiableCredential.type,
              ['VerifiableCredential', 'ProfessionCredential']);
        },
      );

      test(
        'it retrieves the correct issuance date',
        () {
          expect(verifiableCredential.validFrom,
              DateTime.utc(2022, 12, 02, 16, 53, 20));
        },
      );

      test(
        'it retrieves the correct credential subject with a profession position',
        () {
          expect(
              verifiableCredential.credentialSubject['position'], 'Developer');
        },
      );

      test(
        'it retrieves the correct id',
        () {
          expect(verifiableCredential.id, 'vc3');
        },
      );

      test(
        'it retrieves the correct schema',
        () {
          expect(verifiableCredential.credentialSchema, isNotNull);
          expect(
              verifiableCredential.credentialSchema.firstOrNull?.id, 'schema3');
          expect(verifiableCredential.credentialSchema.firstOrNull?.type,
              'JsonSchemaValidator2018');
        },
      );

      test(
        'it does not have an expiry date',
        () {
          expect(verifiableCredential.validUntil, isNull);
        },
      );

      test('it should return true for verifyExpiry', () async {
        expect(
            await vcDataModelVerifier.verifyExpiry(verifiableCredential), true);
      });

      test(
        'it holds the original json data provided to create the instance',
        () {
          expect(
              verifiableCredential.toJson(),
              VerifiableCredentialDataFixtures
                  .jwtCredentialDataModelV11Decoded);
        },
      );

      test(
        'it holds the original raw data provided to create the instance',
        () {
          expect(verifiableCredential.rawData,
              VerifiableCredentialDataFixtures.jwtCredentialDataModelV11);
        },
      );

      group('and amending the initial data', () {
        data = 'aaa';

        test('it does not update the verifiable credential rawData', () {
          expect(verifiableCredential.rawData,
              VerifiableCredentialDataFixtures.jwtCredentialDataModelV11);
        });
      });
    });
  });

  group('When parsing verifiable credentials with a data model v2', () {
    group('and receiving a json structure', () {
      group('with a proof', () {
        var data =
            VerifiableCredentialDataFixtures.credentialWithProofDataModelV20;
        final verifiableCredential = VerifiableCredentialFactory.create(data);
        final vcDataModelVerifier = VcDataModelV2Verifier();
        test(
          'it retrieves the correct issuer',
          () {
            expect(verifiableCredential.issuer,
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
            expect(verifiableCredential.credentialSubject['id'],
                'https://subject.example/subject/3921');
          },
        );

        test(
          'it retrieves the correct id',
          () {
            expect(
                verifiableCredential.id, 'http://example.gov/credentials/3732');
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
          'it should return false for verifyExpiry',
          () async {
            expect(await vcDataModelVerifier.verifyExpiry(verifiableCredential),
                false);
          },
        );

        test(
          'it holds the original json data provided to create the instance',
          () {
            expect(
                verifiableCredential.toJson(),
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV20);
          },
        );

        test(
          'it holds the original raw data provided to create the instance',
          () {
            expect(
                verifiableCredential.rawData,
                VerifiableCredentialDataFixtures
                    .credentialWithProofDataModelV20);
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
                      .credentialWithProofDataModelV20['id']);
            },
          );
        });
      });

      group('without a proof', () {
        test(
          'it throws an unknown format exception',
          () {
            expect(
                () => VerifiableCredentialFactory.create(
                    VerifiableCredentialDataFixtures
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
