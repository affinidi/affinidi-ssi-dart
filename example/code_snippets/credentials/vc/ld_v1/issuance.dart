// ignore_for_file: avoid_print
import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

import '../../../did/did_signer.dart';

Future<void> main() async {
  // Example seed for deterministic key generation
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

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
    holder: MutableHolder.uri('did:example:1'),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({
        'Fname': 'Fname',
        'Lname': 'Lame',
        'Age': '22',
        'Address': 'Eihhornstr',
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
    unsignedData: VcDataModelV1.fromMutable(credential),
    proofGenerator: proofGenerator,
  );

  // VC as JSON string
  final json = jsonEncode(issuedCredential.toJson());
  print('Issued VC JSON:\n$json');
}
