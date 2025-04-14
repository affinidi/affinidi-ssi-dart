class DidDocumentFixtures {
  static Map<String, dynamic> get didDocumentValid => {
        "id":
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io",
        "authentication": [
          "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0",
          verififcationMethodValid
        ],
        "assertionMethod": [
          "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0",
          verififcationMethodValid
        ],
        "keyAgreement": [
          "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-1",
          verififcationMethodValid
        ],
        "alsoKnownAs": [
          "did:web:ee958780-4507-44fb-9af6-a61fdsda54b0f.atlas.dev.affinidi.io"
        ],
        "capabilityInvocation": [
          "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0",
          verififcationMethodValid
        ],
        "capabilityDelegation": [
          "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-1",
          verififcationMethodValid
        ],
        "verificationMethod": [
          {
            "id":
                "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0",
            "type": "JsonWebKey2020",
            "controller":
                "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io",
            "publicKeyJwk": {
              "crv": "Ed25519",
              "kty": "OKP",
              "x": "g6d8EXXxg9jzrm7H3a-AWoGdKhEKVYF5eUcZsEgZMzQ"
            }
          },
          {
            "id":
                "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-1",
            "type": "JsonWebKey2020",
            "controller":
                "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io",
            "publicKeyJwk": {
              "crv": "P-256",
              "kty": "EC",
              "x": "oazkBDKur0nt556t_2Ew7va7_OhE2nl5z_e2ZKpPZA0",
              "y": "LaAIhQNzWniOzvLxiPP8r0IotHVNWdPvaygXk0KCUp4"
            }
          },
          verififcationMethodValid,
        ],
        "service": [
          serviceEndpointValid,
        ],
        "@context": [
          "https://www.w3.org/ns/did/v1",
          "https://w3id.org/security/suites/jws-2020/v1"
        ]
      };

  static Map<String, dynamic> get didDocumentInvalidWithoutId => {
        "authentication": [
          "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0"
        ],
      };

  static Map<String, dynamic> get didDocumentInvalidAuthentication => {
        "id":
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io",
        "authentication": 0,
      };

  static Map<String, dynamic> get verififcationMethodValid => {
        "id":
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-2",
        "type": "JsonWebKey2020",
        "controller":
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io",
        "publicKeyJwk": {
          "crv": "P-256",
          "kty": "EC",
          "x": "oazkBDKur0nt556t_2Ew7va7_OhE2nl5z_e2ZKpPZA0",
          "y": "LaAIhQNzWniOzvLxiPP8r0IotHVNWdPvaygXk0KCUp4"
        }
      };

  static Map<String, dynamic> get serviceEndpointValid => {
        "id":
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#service",
        "type": "DIDCommMessaging",
        "serviceEndpoint": [
          {
            "accept": ["didcomm/v2"],
            "routingKeys": [],
            "uri":
                "https://ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io"
          },
          {
            "accept": ["didcomm/v2"],
            "routingKeys": [],
            "uri":
                "wss://ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io/ws"
          }
        ]
      };

  static String get didDocumentWithControllerKey =>
      '{"@context":["https://www.w3.org/ns/did/v1","https://ns.did.ai/suites/multikey-2021/v1/"],"id":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","verificationMethod":[{"id":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","controller":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":"Secp256k1Key2021","publicKeyMultibase":"zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"}],"authentication":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"capabilityDelegation":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"capabilityInvocation":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"keyAgreement":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"assertionMethod":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"]}';

  static String get didDocumentWithControllerPeer =>
      '{"@context": ["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"], "id":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","verificationMethod":[{"id":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","controller":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"}],"authentication":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"capabilityDelegation":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"capabilityInvocation":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"keyAgreement":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#z6LSrY3Na7Bkq7f3ktzajpR7vQ4YCjyw9KCT1Y2tnjLLZsV5"],"assertionMethod":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"]}';
}
