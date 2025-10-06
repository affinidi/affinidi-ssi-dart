// ignore_for_file: avoid_print
import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';

import '../did/did_signer.dart';

Future<void> main() async {
  // Example seed for deterministic key generation
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  // Initialize signer using the seed
  final signer = await initSigner(seed);

  // Example with a complex context
  final credential1 = MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([
      'https://www.w3.org/2018/credentials/v1',
      {
        'NameCredentialPersonV1': {
          '@id': 'https://schema.affinity-project.org/NameCredentialPersonV1',
          '@context': {'@version': 1.1, '@protected': true}
        },
        'data': {
          '@id': 'https://schema.affinity-project.org/data',
          '@context': [
            null,
            {
              '@version': 1.1,
              '@protected': true,
              '@vocab': 'https://schema.org/',
              'NamePerson': {
                '@id': 'https://schema.affinity-project.org/NamePerson',
                '@context': {
                  '@version': 1.1,
                  '@protected': true,
                  '@vocab': 'https://schema.org/',
                  'name': 'https://schema.org/name',
                  'givenName': 'https://schema.org/givenName',
                  'fullName': 'https://schema.org/fullName'
                }
              },
              'PersonE': {
                '@id': 'https://schema.affinity-project.org/PersonE',
                '@context': {
                  '@version': 1.1,
                  '@protected': true,
                  '@vocab': 'https://schema.org/'
                }
              },
              'OrganizationE': {
                '@id': 'https://schema.affinity-project.org/OrganizationE',
                '@context': {
                  '@version': 1.1,
                  '@protected': true,
                  '@vocab': 'https://schema.org/',
                  'hasCredential': 'https://schema.org/hasCredential',
                  'industry': 'https://schema.affinity-project.org/industry',
                  'identifiers':
                      'https://schema.affinity-project.org/identifiers'
                }
              },
              'Credential': {
                '@id': 'https://schema.affinity-project.org/Credential',
                '@context': {
                  '@version': 1.1,
                  '@protected': true,
                  '@vocab': 'https://schema.org/',
                  'dateRevoked':
                      'https://schema.affinity-project.org/dateRevoked',
                  'recognizedBy':
                      'https://schema.affinity-project.org/recognizedBy'
                }
              },
              'OrganizationalCredential': {
                '@id':
                    'https://schema.affinity-project.org/OrganizationalCredential',
                '@context': {
                  '@version': 1.1,
                  '@protected': true,
                  '@vocab': 'https://schema.org/',
                  'credentialCategory':
                      'https://schema.affinity-project.org/credentialCategory',
                  'organizationType':
                      'https://schema.affinity-project.org/organizationType',
                  'goodStanding':
                      'https://schema.affinity-project.org/goodStanding',
                  'active': 'https://schema.affinity-project.org/active',
                  'primaryJurisdiction':
                      'https://schema.affinity-project.org/primaryJurisdiction',
                  'identifier': 'https://schema.org/identifier'
                }
              }
            }
          ]
        }
      }
    ]),
    id: Uri.parse('uuid:123456abcd'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    holder: MutableHolder.uri('did:example:1'),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({
        'data': {
          '@type': ['Person', 'PersonE', 'NamePerson'],
          'givenName': 'DenisUpdated',
          'familyName': 'Popov',
        },
      }),
    ],
    credentialSchema: [
      MutableCredentialSchema(
        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
        type: 'JsonSchemaValidator2018',
      ),
    ],
  );

  // example with reference to actual schema.org vocabulary
  final credential2 = MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([
      'https://www.w3.org/2018/credentials/v1',
      {
        'name': 'http://schema.org/name',
        'degree': 'https://schema.org/educationalCredentialAwarded',
        'university': 'https://schemas.org/educationalInstitution'
      }
    ]),
    id: Uri.parse('uuid:123456abcd'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    holder: MutableHolder.uri('did:example:1'),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({
        'id': 'did:example:1234567890',
        'name': 'Alice Doe',
        'degree': 'Bachelor of Science in Computer Science',
        'university': 'Example University'
      }),
    ],
    credentialSchema: [
      MutableCredentialSchema(
        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
        type: 'JsonSchemaValidator2018',
      ),
    ],
  );

  // example where jsonld processor would throw an error
  final credential3 = MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([
      'https://www.w3.org/2018/credentials/v1',
      {
        'schema': 'http://schema.org/',
        'ex': 'https://example.org/terms/',
        'person': {
          '@context': {'name': 'schema:name', 'birthDate': 'schema:birthDate'}
        },
        'education': {
          '@context': {
            'degree': 'schema:educationalCredentialAwarded',
            'alumniOf': 'schema:alumniOf'
          }
        }
      }
    ]),
    id: Uri.parse('uuid:123456abcd'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    holder: MutableHolder.uri('did:example:1'),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({
        'id': 'did:example:1234567890',
        'person': {'name': 'Alice Doe', 'birthDate': '1998-05-12'},
        'education': {
          'degree': 'Bachelor of Science in Computer Science',
          'alumniOf': 'Example University'
        }
      }),
    ],
    credentialSchema: [
      MutableCredentialSchema(
        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
        type: 'JsonSchemaValidator2018',
      ),
    ],
  );

  // Issue VC with LD proof
  final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
  final issuedCredential = await LdVcDm1Suite().issue(
    unsignedData: VcDataModelV1.fromMutable(credential2),
    proofGenerator: proofGenerator,
  );

  // VC as JSON string
  final json = jsonEncode(issuedCredential.toJson());
  print('Issued VC JSON:\n$json');

  // Parse the credential
  final verifiableCredential = UniversalParser.parse(json.toString());

  // Run the integrity verifier
  final verifier = VcIntegrityVerifier();
  final result = await verifier.verify(verifiableCredential);

  // Print results
  print('\n\n\nIntegrity verification result: ${result.isValid}');
  if (!result.isValid) {
    print('Errors: ${result.errors}');
  }
  if (result.warnings.isNotEmpty) {
    print('Warnings: ${result.warnings}');
  }
}
