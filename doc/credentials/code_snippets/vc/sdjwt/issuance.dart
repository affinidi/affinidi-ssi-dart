// ignore_for_file: avoid_print

import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/credential_subject.dart';
import 'package:ssi/src/credentials/models/field_types/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';

import '../../did/did_signer.dart';

void main() async {
  // Example seed for deterministic key generation
  final seed = Uint8List.fromList(List.generate(32, (i) => i + 1));

  // Initialize signer using the seed
  final signer = await initSigner(seed);

  // Create a mutable VC
  final mutableVC = MutableVcDataModelV2(
    context: [DMV2ContextUrl],
    id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
    issuer: Issuer.uri(signer.did),
    type: {'VerifiableCredential', 'UniversityDegreeCredential'},
    validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
    validUntil: DateTime.parse('2028-01-01T12:00:00Z'),
    credentialSubject: [
      MutableCredentialSubject({
        'id': 'did:example:subject',
        'firstName': 'Rain',
        'lastName': 'Bow',
        'degree': {
          'type': 'BachelorDegree',
          'name': 'Bachelor of Science and Arts',
          'gpa': '3.8',
        },
      }),
    ],
  );

  // Define a custom disclosure frame
  final disclosureFrame = {
    'credentialSubject': {
      '_sd': ['firstName', 'lastName'],
      'degree': {
        '_sd': ['gpa'],
      },
    },
  };

  // Issue the credential using SdJwtDm2Suite
  final suite = SdJwtDm2Suite();
  final issuedCredential = await suite.issue(
    unsignedData: VcDataModelV2.fromMutable(mutableVC),
    signer: signer,
    disclosureFrame: disclosureFrame,
  );

  // Print results
  print('Issued SD-JWT VC (serialized):');
  print(issuedCredential.serialized);

  print('Signed Payload: ');
  print(issuedCredential.sdJwt.payload);

  print('All Claims (after resolving disclosures): ');
  print(issuedCredential.sdJwt.claims);
}
