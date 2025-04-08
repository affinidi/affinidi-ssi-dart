import 'package:ssi/src/types.dart';

class VerifiableCredentialDataFixtures {
  static Map<String, dynamic> get credentialWithProofDataModelV11 => {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.io/HITContactsV1R0.jsonld'
        ],
        'id': 'claimId:02-aaaaaa-aaaaaaaaaaa',
        'type': ['VerifiableCredential', 'HITContacts'],
        'holder': {
          'id': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa'
        },
        'credentialSubject': {'email': 'user@affinidi.com'},
        'credentialSchema': {
          'id': 'credentialSchemaId',
          'type': 'credentialSchemaType'
        },
        'issuanceDate': '2024-07-16T20:16:05.648',
        'expirationDate': '2024-07-18T20:16:05.648',
        'issuer': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa',
        'proof': {
          'type': SignatureScheme.ecdsa_secp256k1_sha256.w3cName,
          'created': '2024-07-16T18:16:05Z',
          'proofPurpose': 'assertionMethod',
          'verificationMethod':
              'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa#aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa',
          'jws':
              'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..ee19g6fjm34kb9aG_tGzVyW5-sLq6KvFTBnmOHX3ibBFrikO8xYMp3pCg1SU3gePtSnAVKzyDIfxj1xifGcQHw'
        }
      };

  static Map<String, dynamic> get credentialWithoutProofDataModelV11 => {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.io/HITContactsV1R0.jsonld'
        ],
        'id': 'claimId:02-aaaaaa-aaaaaaaaaaa',
        'type': ['VerifiableCredential', 'HITContacts'],
        'holder': {
          'id': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa'
        },
        'credentialSubject': {'email': 'user@affinidi.com'},
        'credentialSchema': {
          'id': 'credentialSchemaId',
          'type': 'credentialSchemaType'
        },
        'issuanceDate': '2024-07-16T20:16:05.648',
        'expirationDate': '2024-07-18T20:16:05.648',
        'issuer': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa',
      };

  static Map<String, dynamic> get credentialWithProofDataModelV20 => {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2'
        ],
        'id': 'http://example.gov/credentials/3732',
        'type': ['VerifiableCredential', 'ExampleDegreeCredential'],
        'issuer': 'did:example:6fb1f712ebe12c27cc26eebfe11',
        'validFrom': '2010-01-01T19:23:24Z',
        'validUntil': '2020-02-01T19:25:24Z',
        'credentialSubject': {
          'id': 'https://subject.example/subject/3921',
          'degree': {
            'type': 'ExampleBachelorDegree',
            'name': 'Bachelor of Science and Arts'
          }
        },
        'credentialSchema': [
          {
            'id': 'https://example.org/examples/degree.json',
            'type': 'JsonSchema'
          },
          {
            'id': 'https://example.org/examples/alumni.json',
            'type': 'JsonSchema'
          }
        ],
        'credentialStatus': {
          'id':
              'https://api-test.ebsi.eu/trusted-issuers-registry/v5/issuers/did:ebsi:zvHWX359A3CvfJnCYaAiAde/attributes/60ae46e4fe9adffe0bc83c5e5be825aafe6b5246676398cd1ac36b8999e088a8',
          'type': 'EbsiAccreditationEntry'
        },
        'proof': {
          'type': 'DataIntegrityProof',
          'cryptosuite': 'eddsa-rdfc-2022',
          'created': '2021-11-13T18:19:39Z',
          'verificationMethod': 'https://university.example/issuers/14#key-1',
          'proofPurpose': 'assertionMethod',
          'proofValue': 'z58DAdFfa9SkqZMVPxAQp...jQCrfFPP2oumHKtz'
        }
      };

  static Map<String, dynamic> get credentialWithoutProofDataModelV20 => {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2'
        ],
        'id': 'http://example.gov/credentials/3732',
        'type': ['VerifiableCredential', 'ExampleDegreeCredential'],
        'issuer': 'did:example:6fb1f712ebe12c27cc26eebfe11',
        'validFrom': '2010-01-01T19:23:24Z',
        'credentialSubject': {
          'id': 'https://subject.example/subject/3921',
          'degree': {
            'type': 'ExampleBachelorDegree',
            'name': 'Bachelor of Science and Arts'
          }
        },
      };

  static String get jwtCredentialDataModelV11 =>
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJJc3N1ZXIgQyIsImp0aSI6InZjMyIsIm5iZiI6MTY3MDAwMDAwMCwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlByb2Zlc3Npb25DcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoic3ViamVjdDMiLCJwb3NpdGlvbiI6IkRldmVsb3BlciJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoic2NoZW1hMyIsInR5cGUiOiJKc29uU2NoZW1hVmFsaWRhdG9yMjAxOCJ9fX0.HP_0y-TP2HCj9Ch7ftE7Nf7V0j_XT5TfSpxGXEWR2Ys';

  static Map<String, dynamic> get jwtCredentialDataModelV11Decoded => {
        'iss': 'Issuer C',
        'jti': 'vc3',
        'nbf': 1670000000,
        'vc': {
          'type': ['VerifiableCredential', 'ProfessionCredential'],
          'credentialSubject': {'id': 'subject3', 'position': 'Developer'},
          'credentialSchema': {
            'id': 'schema3',
            'type': 'JsonSchemaValidator2018'
          }
        }
      };
}
