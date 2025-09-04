// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';

void main() {
  // Create a sample VcDataModelV2 with realistic fields
  final vc = MutableVcDataModelV2(
    context: MutableJsonLdContext.fromJson([dmV2ContextUrl, 'https://example.org/context/v2']),
    id: Uri.parse('http://example.edu/credentials/abcde'),
    type: {'VerifiableCredential', 'ExampleCredentialV2'},
    issuer: Issuer.uri('did:example:issuerV2'),
    validFrom: DateTime.utc(2024, 01, 01, 12, 0, 0),
    validUntil: DateTime.utc(2025, 01, 01, 12, 0, 0),
    credentialSubject: [
      MutableCredentialSubject(
          {'id': 'did:example:subjectV2', 'email': 'user@affinidi.com'})
    ],
    credentialSchema: [
      MutableCredentialSchema.build(
          domain: 'https://example.org/schemas/v2',
          schema: 'example',
          type: 'JsonSchemaValidator2018')
    ],
    credentialStatus: [
      MutableCredentialStatusV2({
        'id': Uri.parse('https://example.edu/status/v2/1'),
        'type': 'CredentialStatusList2021',
      })
    ],
    refreshService: [MutableRefreshServiceV2(type: 'ManualRefreshService2021')],
    termsOfUse: [
      MutableTermsOfUse(
        id: Uri.parse('https://example.com/tos/v2/1'),
        type: 'IssuerPolicyV2',
      )
    ],
    evidence: [
      MutableEvidence(
        id: Uri.parse('https://example.edu/evidence/v2/1'),
        type: 'DocumentVerificationV2',
      )
    ],
    proof: [
      EmbeddedProof(
        type: 'DataIntegrityProof',
        created: DateTime.utc(2024, 01, 01, 12, 5, 0),
        verificationMethod: 'did:example:issuerV2#keys-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'zABC...',
        cryptosuite: 'eddsa-jcs-2022',
      )
    ],
  );

  // Serialize to JSON and print
  final serialized = vc.toJson();
  print('Serialized VC V2:');
  print(serialized);

  // Deserialize back into VcDataModelV2
  final parsed = VcDataModelV2.fromJson(serialized);
  print('\nParsed VC ID: ${parsed.id}');
  print('Parsed VC Issuer: ${parsed.issuer.id}');
  print('Parsed VC Subject: ${parsed.credentialSubject.first.toJson()}');
  print('Parsed Proof Type: ${parsed.proof.first.type}');
}
