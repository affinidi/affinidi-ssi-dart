// ignore_for_file: avoid_print
import 'dart:convert';

import 'package:ssi/src/credentials/models/field_types/credential_subject.dart';
import 'package:ssi/src/credentials/models/field_types/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';
import 'package:base_codecs/base_codecs.dart';
import '../../did/did_signer.dart';

Future<void> main() async {
  // Example seed for deterministic key generation
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  // Initialize signer using the seed
  final signer = await initSigner(seed);

  // Create the SD-JWT DM2 suite
  final suite = SdJwtDm2Suite();

  // Create a sample verifiable credential
  final credential = MutableVcDataModelV2(
      context: [DMV2ContextUrl],
      id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
      issuer: Issuer.uri(signer.did),
      type: {'VerifiableCredential', 'UniversityDegreeCredential'},
      validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
      validUntil: DateTime.parse('2028-01-01T12:00:00Z'),
      credentialSubject: [
        MutableCredentialSubject({
          'id': 'did:example:subject',
          'degree': {
            'type': 'BachelorDegree',
            'name': 'Bachelor of Science and Arts',
          },
        })
      ]);

  // Issue the VC
  final credentialToSign = VcDataModelV2.fromMutable(credential);
  final issuedCredential =
      await suite.issue(unsignedData: credentialToSign, signer: signer);

  // VC as JSON string
  final json = jsonEncode(issuedCredential.toJson());
  print('Issued VC JSON:\n$json');
}
