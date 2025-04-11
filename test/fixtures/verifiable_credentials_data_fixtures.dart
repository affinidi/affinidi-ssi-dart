import 'dart:convert';

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

  static String get credentialWithProofDataModelV11JsonEncoded =>
      jsonEncode(credentialWithProofDataModelV11);

  static Map<String, dynamic> get credentialWithValidProofDataModelV11 => {
        '@context': [
          "https://www.w3.org/2018/credentials/v1",
          "https://schema.affinidi.com/EmailV1-0.jsonld"
        ],
        'id': "claimId:2b249d9d93f38e3a",
        'type': ["VerifiableCredential", "Email"],
        'credentialSchema': {
          "id": "https://schema.affinidi.com/EmailV1-0.json",
          "type": "JsonSchemaValidator2018"
        },
        'credentialSubject': {"email": "savani.j+dev21@affinidi.com"},
        'holder': {
          "id": "did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf"
        },
        'issuanceDate': "2024-09-04T12:15:23.355Z",
        'issuer': "did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6",
        "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2024-09-04T12:15:29Z",
          "proofPurpose": "assertionMethod",
          "verificationMethod":
              "did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6#zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6",
          "jws":
              "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..lN5GVttiM5den0qU1fcgc1QdCbHhmWgdI3iIp_VyprQtrzT9GK3eQyuT7-C1VBcD-AE7ZYWwdsMNcgsuUmH0Vg"
        },
      };

  static String get credentialWithValidProofDataModelV11JsonEncoded =>
      jsonEncode(credentialWithValidProofDataModelV11);

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
        'id': 'https://example.gov/credentials/3732',
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
        'id': 'https://example.gov/credentials/3732',
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
      'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NodDFaODU4d2hwVlFCdzJjSFBXZ3F2UzhNeHlSS05zZGpvWlJGWjJZM2hyVGgjelEzc2h0MVo4NTh3aHBWUUJ3MmNIUFdncXZTOE14eVJLTnNkam9aUkZaMlkzaHJUaCIsInR5cCI6IkpXVCJ9.eyJuYmYiOjEyNjIzMDQwMDAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvaXNzdWVycy81NjUwNDkiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn19fX0.1oRBHqDYPJuaCKAZntxUBO13N6GDr4N2tInO9hnLgdMkREc7FVT5sOewkpMjbbK6G5wJa9FiCyLkpM1GyGw8_g';

  static String get jwtCredentialDataModelV11InvalidSig =>
      'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NodDFaODU4d2hwVlFCdzJjSFBXZ3F2UzhNeHlSS05zZGpvWlJGWjJZM2hyVGgjelEzc2h0MVo4NTh3aHBWUUJ3MmNIUFdncXZTOE14eVJLTnNkam9aUkZaMlkzaHJUaCIsInR5cCI6IkpXVCJ9.eyJuYmYiOjEyNjIzMDQwMDAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvaXNzdWVycy81NjUwNDkiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn19fX0.1oRBHqDYPJuaCKAZntxUBO13N6GDr4N2tInO9hnLgdMkREc7FVT5sOewkpMjbbK6G5wJa9FiCyLkpM1GyGw7_g';

  static Map<String, dynamic> get jwtCredentialDataModelV11Decoded => {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/565049",
        "issuanceDate": "2010-01-01T00:00:00.000Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts"
          }
        }
      };
}
