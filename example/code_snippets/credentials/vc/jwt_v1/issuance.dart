// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/credentials/jwt/jwt_dm_v1_suite.dart';
import 'package:ssi/src/credentials/models/field_types/credential_subject.dart';
import 'package:ssi/src/credentials/models/field_types/issuer.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';

import '../../../did/did_signer.dart';

void main() async {
  // Example seed for deterministic key generation
  final seed = Uint8List.fromList(List.generate(32, (i) => i + 1));

  // Initialize signer using the seed
  final signer = await initSigner(seed);

  // Create a sample verifiable credential
  final credential = MutableVcDataModelV1(
    context: [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
    ],
    id: Uri.parse('uuid:123456abcd'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    issuanceDate: DateTime.now(),
    credentialSubject: [
      MutableCredentialSubject({
        'id': 'did:example:holder123', // Holder DID is required for JWT VC
        'Fname': 'Fname',
        'Lname': 'Lame',
        'Age': '22',
        'Address': 'Eihhornstr',
      }),
    ],
  );

  // Issue VC as JWT
  final suite = JwtDm1Suite();
  final issuedJwtVc = await suite.issue(
    unsignedData: VcDataModelV1.fromMutable(credential),
    signer: signer,
  );

  // Print the issued JWT VC
  print('Issued JWT VC:\n${issuedJwtVc.serialized}');

  // You can also decode the payload for inspection
  final decodedPayload = issuedJwtVc.jws.payload;
  print('\nDecoded Payload:');
  print(jsonEncode(decodedPayload));
}
