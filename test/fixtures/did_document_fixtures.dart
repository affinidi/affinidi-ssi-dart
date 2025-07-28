class DidDocumentFixtures {
  static Map<String, dynamic> get didDocumentValid => {
        'id': 'did:web:example.com',
        'authentication': [
          'did:web:example.com#key-0',
          verififcationMethodValid
        ],
        'assertionMethod': [
          'did:web:example.com#key-0',
          verififcationMethodValid
        ],
        'keyAgreement': ['did:web:example.com#key-1', verififcationMethodValid],
        'alsoKnownAs': ['did:web:alias.example.com'],
        'capabilityInvocation': [
          'did:web:example.com#key-0',
          verififcationMethodValid
        ],
        'capabilityDelegation': [
          'did:web:example.com#key-1',
          verififcationMethodValid
        ],
        'verificationMethod': [
          {
            'id': 'did:web:example.com#key-0',
            'type': 'JsonWebKey2020',
            'controller': 'did:web:example.com',
            'publicKeyJwk': {
              'crv': 'Ed25519',
              'kty': 'OKP',
              'x': 'g6d8EXXxg9jzrm7H3a-AWoGdKhEKVYF5eUcZsEgZMzQ'
            }
          },
          {
            'id': 'did:web:example.com#key-1',
            'type': 'JsonWebKey2020',
            'controller': 'did:web:example.com',
            'publicKeyJwk': {
              'crv': 'P-256',
              'kty': 'EC',
              'x': 'oazkBDKur0nt556t_2Ew7va7_OhE2nl5z_e2ZKpPZA0',
              'y': 'LaAIhQNzWniOzvLxiPP8r0IotHVNWdPvaygXk0KCUp4'
            }
          },
          verififcationMethodValid,
        ],
        'service': [
          serviceEndpointValid,
        ],
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1'
        ]
      };

  static Map<String, dynamic> get didDocumentInvalidWithoutId => {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1'
        ],
        'authentication': ['did:web:example.com#key-0'],
      };

  static Map<String, dynamic> get didDocumentInvalidWithoutContext => {
        'authentication': ['did:web:example.com#key-0'],
      };

  static Map<String, dynamic> get didDocumentInvalidAuthentication => {
        'id': 'did:web:example.com',
        'authentication': 0,
      };

  static Map<String, dynamic> get verififcationMethodValid => {
        'id': 'did:web:example.com#key-2',
        'type': 'JsonWebKey2020',
        'controller': 'did:web:example.com',
        'publicKeyJwk': {
          'crv': 'P-256',
          'kty': 'EC',
          'x': 'oazkBDKur0nt556t_2Ew7va7_OhE2nl5z_e2ZKpPZA0',
          'y': 'LaAIhQNzWniOzvLxiPP8r0IotHVNWdPvaygXk0KCUp4'
        }
      };

  static Map<String, dynamic> get serviceEndpointValid => {
        'id': 'did:web:example.com#service',
        'type': 'GenericService',
        'serviceEndpoint': [
          {
            'accept': ['application/json'],
            'routingKeys': <String>[],
            'uri': 'https://example.com'
          },
          {
            'accept': ['application/json'],
            'routingKeys': <String>[],
            'uri': 'wss://example.com/ws'
          }
        ]
      };

  static String get didDocumentWithControllerKey =>
      '{"@context":["https://www.w3.org/ns/did/v1","https://ns.did.ai/suites/multikey-2021/v1/"],"id":"did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R","verificationMethod":[{"id":"did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R#zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R","controller":"did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R","type":"Secp256k1Key2021","publicKeyMultibase":"zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R"}],"authentication":["did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R#zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R"],"capabilityDelegation":["did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R#zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R"],"capabilityInvocation":["did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R#zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R"],"keyAgreement":["did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R#zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R"],"assertionMethod":["did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R#zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R"]}';

  static String get didDocumentWithControllerPeer =>
      '{"id":"did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka","@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"verificationMethod":[{"id":"did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka","controller":"did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka","type":"Multikey","publicKeyMultibase":"z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka"},{"id":"did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6LSt6UM88iki6ZgQ6ahzhHkZBWshULHpHSNZ6DDXnatm7eu","controller":"did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka","type":"Multikey","publicKeyMultibase":"z6LSt6UM88iki6ZgQ6ahzhHkZBWshULHpHSNZ6DDXnatm7eu"}],"authentication":["did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka"],"capabilityDelegation":["did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka"],"capabilityInvocation":["did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka"],"keyAgreement":["did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6LSt6UM88iki6ZgQ6ahzhHkZBWshULHpHSNZ6DDXnatm7eu"],"assertionMethod":["did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka#z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka"]}';
}
