/// Digital Bazaar test vectors for JCS cryptosuites.
///
/// These test vectors are provided by Digital Bazaar for interoperability testing
/// of ecdsa-jcs-2019 and eddsa-jcs-2022 cryptosuites.
class JcsTestVectors {
  /// ECDSA JCS 2019 test vector from Digital Bazaar.
  static Map<String, dynamic> get ecdsaJcs2019TestVector => {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2'
        ],
        'id': 'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',
        'type': ['VerifiableCredential', 'AlumniCredential'],
        'name': 'Alumni Credential',
        'description': 'A minimum viable example of an Alumni Credential.',
        'issuer': 'did:key:zDnaeoWd5aKSeZ8QAimcVrLGEU2SnWCrY4wQneAAk5NhQyn8U',
        'validFrom': '2023-01-01T00:00:00Z',
        'credentialSubject': {
          'id': 'did:example:abcdefgh',
          'alumniOf': 'The School of Examples'
        },
        'proof': {
          'type': 'DataIntegrityProof',
          'created': '2023-02-24T23:36:38Z',
          'verificationMethod':
              'did:key:zDnaeoWd5aKSeZ8QAimcVrLGEU2SnWCrY4wQneAAk5NhQyn8U#zDnaeoWd5aKSeZ8QAimcVrLGEU2SnWCrY4wQneAAk5NhQyn8U',
          'cryptosuite': 'ecdsa-jcs-2019',
          'proofPurpose': 'assertionMethod',
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          'proofValue':
              'z42wCWvyMAGP77wYLTyciWjhCbuFrRzS93iMDEg3GWUaDUTnc27uQYHg7p6JwA2Pg36JS2Ng1RuDgbLwNhGMDHaMc'
        }
      };

  /// EdDSA JCS 2022 test vector from Digital Bazaar.
  static Map<String, dynamic> get eddsaJcs2022TestVector => {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2'
        ],
        'id': 'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',
        'type': ['VerifiableCredential', 'AlumniCredential'],
        'name': 'Alumni Credential',
        'description': 'A minimum viable example of an Alumni Credential.',
        'issuer': 'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2',
        'validFrom': '2023-01-01T00:00:00Z',
        'credentialSubject': {
          'id': 'did:example:abcdefgh',
          'alumniOf': 'The School of Examples'
        },
        'proof': {
          'type': 'DataIntegrityProof',
          'created': '2023-02-24T23:36:38Z',
          'verificationMethod':
              'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2',
          'cryptosuite': 'eddsa-jcs-2022',
          'proofPurpose': 'assertionMethod',
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          'proofValue':
              'z5EhYRJkfPLkoT92FPXN8KK6M9rsBhq3xs19GBSsA6VdNYH4QMKSyNuA2Gfznz9QthVD7Rz3HTAfqxxay23htUpTg'
        }
      };
}
