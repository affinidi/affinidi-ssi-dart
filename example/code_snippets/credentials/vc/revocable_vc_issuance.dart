// ignore_for_file: avoid_print
import 'dart:convert';
import 'dart:io';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

import '../../did/did_signer.dart';

// Optional: create a mock Revocation List Credential to host separately.
// In production this should be issued & published at revocationListCredential URL.
Map<String, dynamic> createRevocationListCredential({
  required String listCredentialId,
  required String issuerDid,
  required List<int> bitstring,
}) {
  // Compress and base64url-encode the raw bitstring.
  final compressed = gzip.encode(bitstring);
  final encodedList = base64Url.encode(compressed);

  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    'id': listCredentialId,
    'type': ['VerifiableCredential', 'RevocationList2020'],
    'issuer': issuerDid,
    'credentialSubject': {
      'id': '$listCredentialId#list',
      'type': 'RevocationList2020',
      'encodedList': encodedList,
    }
  };
}

Future<void> main() async {
  // Deterministic seed (replace with secure random generation for real usage)
  final seed = hexDecode(
      'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd');
  final signer = await initSigner(seed);

  // Build (mock) revocation list credential you would host at the referenced URL
  final revocationListCredentialUrl = 'https://example.org/revocation-list';
  final revocationList = createRevocationListCredential(
    listCredentialId: revocationListCredentialUrl,
    issuerDid: signer.did,
    // Two bytes => 16 bits. 0x00 then 0x80 sets bit 7 (index 15) while index 0 is 0 (non-revoked).
    bitstring: [0x00, 0x80],
  );
  print('Mock Revocation List Credential:\n${jsonEncode(revocationList)}\n');

  // Create unsigned VC including credentialStatus referencing the revocation list
  final unsigned = MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
      'https://w3id.org/vc-revocation-list-2020/v1',
    ]),
    id: Uri.parse('uuid:123456abcd'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    holder: MutableHolder.uri('did:example:holder123'),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({
        'id': 'did:example:holder123',
        'Fname': 'Alice',
        'Lname': 'Example',
        'Age': '29',
        'Address': '123 Demo Street',
      }),
    ],
    credentialSchema: [
      MutableCredentialSchema(
        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
        type: 'JsonSchemaValidator2018',
      ),
    ],
    credentialStatus: MutableCredentialStatusV1({
      'id': 'urn:uuid:revocation-list-0',
      'type': 'RevocationList2020Status',
      'revocationListIndex': '0', // Index 0 is non-revoked per our bitstring
      'revocationListCredential': revocationListCredentialUrl,
    }),
  );

  // Issue Linked Data VC (Secp256k1Signature2019)
  final ldProofGenerator = Secp256k1Signature2019Generator(signer: signer);
  final issuedLdVc = await LdVcDm1Suite().issue(
    unsignedData: VcDataModelV1.fromMutable(unsigned),
    proofGenerator: ldProofGenerator,
  );
  print(
      'Issued Linked Data VC (revocable):\n${jsonEncode(issuedLdVc.toJson())}\n');

  // Issue JWT VC with same credentialStatus
  final jwtSuite = JwtDm1Suite();
  final issuedJwtVc = await jwtSuite.issue(
    unsignedData: VcDataModelV1.fromMutable(unsigned),
    signer: signer,
  );
  print('Issued JWT VC (revocable):\n${issuedJwtVc.serialized}\n');
  print('Decoded JWT Payload:\n${jsonEncode(issuedJwtVc.jws.payload)}');

  // To simulate revocation later: update the bitstring so index 0 bit becomes 1, re-host revocation list.
  // Then a verifier using RevocationList2020Verifier would detect revocation.
}
