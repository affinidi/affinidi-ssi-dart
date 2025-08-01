import 'dart:convert';
import 'dart:io';

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
          'type': 'Ed25519Signature2020',
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
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/EmailV1-0.jsonld'
        ],
        'id': 'claimId:2b249d9d93f38e3a',
        'type': ['VerifiableCredential', 'Email'],
        'credentialSchema': {
          'id': 'https://schema.affinidi.com/EmailV1-0.json',
          'type': 'JsonSchemaValidator2018'
        },
        'credentialSubject': {'email': 'savani.j+dev21@affinidi.com'},
        'holder': {
          'id': 'did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf'
        },
        'issuanceDate': '2024-09-04T12:15:23.355Z',
        'issuer': 'did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6',
        'proof': {
          'type': 'EcdsaSecp256k1Signature2019',
          'created': '2024-09-04T12:15:29Z',
          'proofPurpose': 'assertionMethod',
          'verificationMethod':
              'did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6#zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6',
          'jws':
              'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..lN5GVttiM5den0qU1fcgc1QdCbHhmWgdI3iIp_VyprQtrzT9GK3eQyuT7-C1VBcD-AE7ZYWwdsMNcgsuUmH0Vg'
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
        'expirationDate': '3024-07-18T20:16:05.648',
        'issuer': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa',
      };

  static String get credentialWithProofDataModelV20String =>
      jsonEncode(credentialWithProofDataModelV20);

  static Map<String, dynamic> get credentialWithProofDataModelV20 => {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2'
        ],
        'id': 'https://example.gov/credentials/3732',
        'type': ['VerifiableCredential', 'ExampleDegreeCredential'],
        'issuer': 'did:example:6fb1f712ebe12c27cc26eebfe11',
        'validFrom': '2010-01-01T19:23:24.000Z',
        'validUntil': '2020-02-01T19:25:24.000Z',
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

  static String get expiringCredentialWithValidProofDataModelV11String =>
      '{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"issuanceDate":"2025-04-22T11:23:37.513399","expirationDate":"2026-04-22T11:23:37.513400","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"holder":{"id":"did:example:1"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T11:23:37.514746","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..CcRHMEsMLurFKqpGlX7RwncS1e5GKwJPaKdJGeyK_yEoSiWJKekboeWnOcCuH3QJE-8rMsCdmcNmR1UyXucA_Q"}}';
  static Map<String, dynamic>
      get expiringCredentialWithValidProofDataModelV11 =>
          jsonDecode(expiringCredentialWithValidProofDataModelV11String)
              as Map<String, dynamic>;

  static String get credentialWithValidProofDataModelV20String =>
      '{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"validFrom":"2025-04-22T10:14:50.323952","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T10:14:50.325530","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..8zzMdjUNQSpoh6hd-IOYtxxuD45MAd0ZNgqyiUJMKWMbkTqYQTxouzNMGTnFfRY8wMxt9VYgV-vBWb-99iDniw"}}';

  static Map<String, dynamic> get credentialWithValidProofDataModelV20 =>
      jsonDecode(credentialWithValidProofDataModelV20String)
          as Map<String, dynamic>;

  static String get expiringCredentialWithValidProofDataModelV20String =>
      '{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"validFrom":"2025-04-22T11:40:21.359650","validUntil":"2026-04-22T11:40:21.359650","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T11:40:21.361346","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..wogMzfg-au-YTXTEZHv6uOiKYO7DxF4eAl1zoN1gwh5qk_OfvK4wniG3k0PiYA7jQZV-HBUBAdhCAhTbn3Zw3A"}}';

  static Map<String, dynamic>
      get expiringCredentialWithValidProofDataModelV20 =>
          jsonDecode(expiringCredentialWithValidProofDataModelV20String)
              as Map<String, dynamic>;

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

  static String get sdJwtWithValidSig =>
      'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NoVTROQ1A5SG1jSGE0SE5rd0p6V2dXN0xlcG9jRWNDZ0h2Z0RmZUxxZ2dvVmYjelEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsInR5cCI6InNkK2p3dCJ9.eyJpYXQiOjE3NDQ2NDYwMDgsImlzcyI6ImRpZDprZXk6elEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsIm5iZiI6MTY3MjU3NDQwMCwiZXhwIjoxODMwMzQwODAwLCJzdWIiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIl0sImlzc3VlciI6ImRpZDprZXk6elEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpZCI6InVybjp1dWlkOjEyMzRhYmNkLTEyMzQtYWJjZC0xMjM0LWFiY2QxMjM0YWJjZCIsInZhbGlkRnJvbSI6IjIwMjMtMDEtMDFUMTI6MDA6MDAuMDAwWiIsInZhbGlkVW50aWwiOiIyMDI4LTAxLTAxVDEyOjAwOjAwLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsicnRXOFNIYUFtdy10b3dsOGh6b0p4cHBiaU1aLXNnWlI4S2k2VzVkNC1BayIsIlVKcFpDQzdfNGpJbkZKM0NuWXhRVkxsSmNNMHJjbmpHazloR3dnWWh1Y1kiXX0sIl9zZF9hbGciOiJzaGEtMjU2In0.INMg_DV9bZ4lPnmJd92f6ZqA6RXMLByhNh4Ta7i-Cj8ilmwpda4OfqdJu0ZS3uNKvQE0_enKy2YMbDrCbVs7mg~WyIyUVpNNnJHQWhOcjRBbTZMREoteTl3IiwiaWQiLCJkaWQ6ZXhhbXBsZTpzdWJqZWN0Il0=~WyJrUUtIVC1WZUMxdWVSLXVmNEZHN0tBIiwiZGVncmVlIix7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn1d~';

  static Map<String, dynamic> get jwtCredentialDataModelV11Decoded => {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://www.w3.org/2018/credentials/examples/v1'
        ],
        'id': 'http://example.edu/credentials/3732',
        'type': ['VerifiableCredential', 'UniversityDegreeCredential'],
        'issuer': 'https://example.edu/issuers/565049',
        'issuanceDate': '2010-01-01T00:00:00.000Z',
        'credentialSubject': {
          'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
          'degree': {
            'type': 'BachelorDegree',
            'name': 'Bachelor of Science and Arts'
          }
        }
      };

  static String ldVcDm1ValidStringFromCwe = r'''
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

  // Helper to create compressed encodedList
  static String _createCompressedEncodedList(List<int> bitstring) {
    final compressed = gzip.encode(bitstring);
    return base64Url.encode(compressed);
  }

// Revocation list credential fixture
  static Map<String, dynamic> get revocationListCredential => {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        'id': 'https://example.org/revocation-list',
        'type': ['VerifiableCredential', 'RevocationList2020'],
        'issuer': 'did:example:issuer',
        'credentialSubject': {
          'id': 'https://example.org/revocation-list#list',
          'type': 'RevocationList2020',
          'encodedList': _createCompressedEncodedList([0x00, 0x80]),
        },
        'proof': {
          'type': 'EcdsaSecp256k1Signature2019',
          'created': '2025-04-22T10:00:00Z',
          'proofPurpose': 'assertionMethod',
          'verificationMethod': 'did:example:issuer#key1',
          'jws': 'mock-jws'
        }
      };

  // Credential with non-revoked status, based on ldVcDm1ValidStringFromCwe with URN id
  static String get credentialWithNonRevokedStatusString => r'''
  {
      "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld",
          "https://w3id.org/vc-revocation-list-2020/v1"
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
      "credentialStatus": {
          "id": "urn:uuid:revocation-list-0",
          "type": "RevocationList2020Status",
          "revocationListIndex": "0",
          "revocationListCredential": "https://example.org/revocation-list"
      },
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2025-04-11T15:20:35Z",
          "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jL90Nk1rSfgBXgZJif44x1KkdD0iYgkRjTfChEb0W0gJ6HDDc5BVE5jb1osse7JEueSSJcYaAMfbh_2QsOdcSA"
      }
  }
  ''';

  static String get credentialWithRevokedStatusString => r'''
  {
      "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld",
          "https://w3id.org/vc-revocation-list-2020/v1"
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
      "credentialStatus": {
          "id": "urn:uuid:revocation-list-0",
          "type": "RevocationList2020Status",
          "revocationListIndex": "15",
          "revocationListCredential": "https://example.org/revocation-list"
      },
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2025-04-11T15:20:35Z",
          "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jL90Nk1rSfgBXgZJif44x1KkdD0iYgkRjTfChEb0W0gJ6HDDc5BVE5jb1osse7JEueSSJcYaAMfbh_2QsOdcSA"
      }
  }
  ''';

  // V2 credential with non-revoked status
  static String get credentialWithNonRevokedStatusV2String => r'''
  {
      "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld",
          "https://w3id.org/vc-revocation-list-2020/v1"
      ],
      "id": "uuid:123456abcd",
      "type": ["VerifiableCredential", "UserProfile"],
      "issuer": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
      "validFrom": "2025-04-22T10:14:50.323952Z",
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
      "credentialStatus": {
          "id": "urn:uuid:revocation-list-0",
          "type": "RevocationList2020Status",
          "revocationListIndex": "0",
          "revocationListCredential": "https://example.org/revocation-list"
      },
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
          "created": "2025-04-22T10:14:50.325530Z",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..8zzMdjUNQSpoh6hd-IOYtxxuD45MAd0ZNgqyiUJMKWMbkTqYQTxouzNMGTnFfRY8wMxt9VYgV-vBWb-99iDniw"
      }
  }
  ''';

  // V2 credential with revoked status
  static String get credentialWithRevokedStatusV2String => r'''
  {
      "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld",
          "https://w3id.org/vc-revocation-list-2020/v1"
      ],
      "id": "uuid:123456abcd",
      "type": ["VerifiableCredential", "UserProfile"],
      "issuer": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
      "validFrom": "2025-04-22T10:14:50.323952Z",
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
      "credentialStatus": {
          "id": "urn:uuid:revocation-list-0",
          "type": "RevocationList2020Status",
          "revocationListIndex": "8",
          "revocationListCredential": "https://example.org/revocation-list"
      },
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2025-04-11T15:20:35Z",
          "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jL90Nk1rSfgBXgZJif44x1KkdD0iYgkRjTfChEb0W0gJ6HDDc5BVE5jb1osse7JEueSSJcYaAMfbh_2QsOdcSA"
      }
  }
  ''';

  // V2 credential with multiple non-revoked and revoked statuses
  static String get credentialWithMultipleNonRevokedStatusV2String => r'''
  {
      "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "id": "uuid:123456abcd",
      "type": ["VerifiableCredential", "UserProfile"],
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
      "credentialStatus": [
          {
              "id": "urn:uuid:revocation-list-0",
              "type": "RevocationList2020Status",
              "revocationListIndex": "0",
              "revocationListCredential": "https://example.org/revocation-list"
          },
          {
              "id": "urn:uuid:revocation-list-1",
              "type": "RevocationList2020Status",
              "revocationListIndex": "1",
              "revocationListCredential": "https://example.org/revocation-list"
          }
      ],
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2025-04-11T15:20:35Z",
          "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jL90Nk1rSfgBXgZJif44x1KkdD0iYgkRjTfChEb0W0gJ6HDDc5BVE5jb1osse7JEueSSJcYaAMfbh_2QsOdcSA"
      }
  }
  ''';

  // V2 credential with multiple non-revoked and revoked statuses
  static String get credentialWithMixedStatusV2String => r'''
  {
      "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "id": "uuid:123456abcd",
      "type": ["VerifiableCredential", "UserProfile"],
      "issuer": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
      "validFrom": "2025-04-22T10:14:50.323952Z",
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
      "credentialStatus": [
          {
              "id": "urn:uuid:revocation-list-0",
              "type": "RevocationList2020Status",
              "revocationListIndex": "0",
              "revocationListCredential": "https://example.org/revocation-list"
          },
          {
              "id": "urn:uuid:revocation-list-1",
              "type": "RevocationList2020Status",
              "revocationListIndex": "15",
              "revocationListCredential": "https://example.org/revocation-list"
          }
      ],
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
          "created": "2025-04-22T10:14:50.325530Z",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..8zzMdjUNQSpoh6hd-IOYtxxuD45MAd0ZNgqyiUJMKWMbkTqYQTxouzNMGTnFfRY8wMxt9VYgV-vBWb-99iDniw"
      }
  }
  ''';

  static String get credentialWithEcdsaRdfc2019ByDigitalBazaar => r'''
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://schema.affinidi.io/TEmailV1R0.jsonld"
    ],
    "issuer": {
      "id": "did:key:zDnaexVEhCGacGuuZ3QDkc68BsiAZKbc9XJBXkTeYDsKNvp9V"
    },
    "type": [
      "VerifiableCredential",
      "Email"
    ],
    "id": "claimid:ee3882a6b3058195",
    "credentialSchema": {
      "id": "https://schema.affinidi.io/TEmailV1R0.json",
      "type": "JsonSchemaValidator2018"
    },
    "issuanceDate": "2025-07-25T07:31:47.035901Z",
    "credentialSubject": {
      "email": "ivan.b@affinidi.com"
    },
    "proof": {
      "type": "DataIntegrityProof",
      "created": "2025-07-25T09:31:47.036239",
      "verificationMethod": "did:key:zDnaexVEhCGacGuuZ3QDkc68BsiAZKbc9XJBXkTeYDsKNvp9V#zDnaexVEhCGacGuuZ3QDkc68BsiAZKbc9XJBXkTeYDsKNvp9V",
      "proofPurpose": "assertionMethod",
      "cryptosuite": "ecdsa-rdfc-2019",
      "proofValue": "z4PRpVJGoS4bQsCUM7xm7TGySx2Q2vEk71tSrkWdUq4bxnR3qUT61rMptg21FvuifVcaNvxQhauY9Jmd66XnL7fSw"
    }
  }
  ''';

  static String get credentialWithEddsaRdfc2022ByDigitalBazaar => r'''
  {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": [
      "VerifiableCredential",
      "AlumniCredential"
    ],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:abcdefgh",
      "alumniOf": "The School of Examples"
    },
    "proof": {
      "type": "DataIntegrityProof",
      "created": "2023-02-24T23:36:38Z",
      "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
      "cryptosuite": "eddsa-rdfc-2022",
      "proofPurpose": "assertionMethod",
      "proofValue": "z3ZNYxHhm9bjNcFXnWFkadUAUvFpQK5k3bDaUgL7HQ7BSSpMgBYLRegRzNNv4DQ8Gv8oQeUQT74Fqe4n3C5gchZYv"
    }
  }
  ''';

  static String get credentialWithEcdsaSecp256k1Signature2019ByVault => r'''
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://schema.affinidi.io/TEmailV1R0.jsonld"
    ],
    "credentialSchema": {
      "id": "https://schema.affinidi.io/TEmailV1R0.json",
      "type": "JsonSchemaValidator2018"
    },
    "credentialSubject": {
      "email": "ivan.b@affinidi.com"
    },
    "holder": {
      "id": "did:key:zQ3shnHRFYxDpASTxaTFBMcqtFASxyzctDx8xYj2USw7QUaLb"
    },
    "id": "claimId:ee3882a6b3058195",
    "issuanceDate": "2025-01-23T21:01:23.162Z",
    "issuer": "did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6",
    "proof": {
      "type": "EcdsaSecp256k1Signature2019",
      "created": "2025-01-23T21:01:31Z",
      "verificationMethod": "did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6#zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6",
      "proofPurpose": "assertionMethod",
      "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..ZwNL-5Gva80Xc0FR6v1R6wCVPPMAYzriWu6_szFD48YGPNQJPV66XsDHNjTGyQOyuRy7a3srX3diI5_1527Ttg"
    },
    "type": [
      "VerifiableCredential",
      "Email"
    ]
  }
  ''';
}
