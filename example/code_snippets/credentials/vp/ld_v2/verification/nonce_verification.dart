// ignore_for_file: avoid_print

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

import '../../../../../../test/test_utils.dart';

void main() async {
  // Deterministic seed for key generation
  final testSeed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  // Initialize signer using the seed
  final signer = await initEdSigner(testSeed);

  // Create the SD-JWT DM2 suite
  final suite = LdVcDm2Suite();

  // Create a sample verifiable credential
  final credential = MutableVcDataModelV2(
      context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
      id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
      issuer: Issuer.uri(signer.did),
      type: {'VerifiableCredential', 'UniversityDegreeCredential'},
      validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
      validUntil: DateTime.parse('2028-01-01T12:00:00Z'),
      credentialSubject: [
        MutableCredentialSubject({
          'id': signer.did,
          'degree': {
            'type': 'BachelorDegree',
            'name': 'Bachelor of Science and Arts',
          },
        })
      ]);

  // Issue the VC
  final credentialToSign = VcDataModelV2.fromMutable(credential);
  final proofGenerator = DataIntegrityEddsaJcsGenerator(signer: signer);
  final issuedCredential = await suite.issue(
      unsignedData: credentialToSign, proofGenerator: proofGenerator);

  print('=== Issued Verifiable Credential ===');
  print(issuedCredential.serialized);
  print('');

  // Parse the VC string
  final ldV2VC = UniversalParser.parse(issuedCredential.serialized);
  // Build the unsigned Verifiable Presentation
  final v2Vp = MutableVpDataModelV2(
      context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
      id: Uri.parse('testVpV2'),
      type: {'VerifiablePresentation'},
      holder: MutableHolder.uri(signer.did),
      verifiableCredential: [ldV2VC]);

// Issue the VP with the proof attached
  final issuedPresentation = await LdVpDm2Suite().issue(
      unsignedData: VpDataModelV2.fromMutable(v2Vp),
      proofGenerator: proofGenerator);

  print('=== Issued Verifiable Presentation ===');
  print(issuedPresentation.serialized);
  print('');

  final verificationStatus =
      await UniversalPresentationVerifier().verify(issuedPresentation);

  // Print results
  print('=== Verification Results ===');
  print('Is VP valid? ${verificationStatus.isValid}');
  if (!verificationStatus.isValid) {
    print('Errors: ${verificationStatus.errors}');
  }
  if (verificationStatus.warnings.isNotEmpty) {
    print('Warnings: ${verificationStatus.warnings}');
  }
}
