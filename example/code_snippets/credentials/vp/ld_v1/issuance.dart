// ignore_for_file: avoid_print

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';

import '../../../did/did_signer.dart';

Future<void> main() async {
  // Deterministic seed for key generation
  final testSeed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  // Initialize signer from seed
  final signer = await initSigner(testSeed);

  // Load example credentials (LD VC V1 + SD-JWT V1)
  final ldV1VC = UniversalParser.parse(v1VcString);
  final jwtV1VC = UniversalParser.parse(jwtVcString);

  // Create a Verifiable Presentation (V1)
  final v1Vp = MutableVpDataModelV1(
    context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
    id: Uri.parse('testVpV1Id'),
    type: {'VerifiablePresentation'},
    holder: MutableHolder.uri(signer.did),
    verifiableCredential: [ldV1VC, jwtV1VC],
  );

  // create a proof Generator
  final proofGenerator = Secp256k1Signature2019Generator(
    signer: signer,
    proofPurpose: ProofPurpose.authentication,
  );

  // Issue the VP using the V1 suite
  final vpToSign = VpDataModelV1.fromMutable(v1Vp);
  final issuedVp = await LdVpDm1Suite()
      .issue(unsignedData: vpToSign, proofGenerator: proofGenerator);

  // Output result
  print('Serialized VP:\n${issuedVp.serialized}');
}

const v1VcString =
    '{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"holder":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"issuanceDate":"2025-11-14T12:21:43.307375Z","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-14T13:21:43.319786","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..MTF_UE8fiho3bAOZVrL_bFL2fucXiiTh41cYUcReZrkSN-tyQdl_sMBP84HNK79W2lDrp2KStd2z34JlqpIEng"}}';
const jwtVcString =
    'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NodDFaODU4d2hwVlFCdzJjSFBXZ3F2UzhNeHlSS05zZGpvWlJGWjJZM2hyVGgjelEzc2h0MVo4NTh3aHBWUUJ3MmNIUFdncXZTOE14eVJLTnNkam9aUkZaMlkzaHJUaCIsInR5cCI6IkpXVCJ9.eyJuYmYiOjEyNjIzMDQwMDAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvaXNzdWVycy81NjUwNDkiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn19fX0.1oRBHqDYPJuaCKAZntxUBO13N6GDr4N2tInO9hnLgdMkREc7FVT5sOewkpMjbbK6G5wJa9FiCyLkpM1GyGw8_g';
