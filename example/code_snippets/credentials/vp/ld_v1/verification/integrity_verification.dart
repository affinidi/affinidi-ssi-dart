// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_integrity_verifier.dart';

void main() async {
  // Parse the VP string into a VerifiablePresentation object
  final v1Vp = UniversalPresentationParser.parse(v1VpString);

  // Create a VpIntegrityVerifier
  final verificationStatus = await VpIntegrityVerifier().verify(v1Vp);

  // Print results
  print('Is VP valid? ${verificationStatus.isValid}');
  if (!verificationStatus.isValid) {
    print('Errors: ${verificationStatus.errors}');
  }
  if (verificationStatus.warnings.isNotEmpty) {
    print('Warnings: ${verificationStatus.warnings}');
  }
}

// Example VP string
const v1VpString =
    '{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"testVpV1Id","type":["VerifiablePresentation"],"holder":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"holder":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"issuanceDate":"2025-11-14T12:21:43.307375Z","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-14T13:21:43.319786","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..MTF_UE8fiho3bAOZVrL_bFL2fucXiiTh41cYUcReZrkSN-tyQdl_sMBP84HNK79W2lDrp2KStd2z34JlqpIEng"}},"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NodDFaODU4d2hwVlFCdzJjSFBXZ3F2UzhNeHlSS05zZGpvWlJGWjJZM2hyVGgjelEzc2h0MVo4NTh3aHBWUUJ3MmNIUFdncXZTOE14eVJLTnNkam9aUkZaMlkzaHJUaCIsInR5cCI6IkpXVCJ9.eyJuYmYiOjEyNjIzMDQwMDAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvaXNzdWVycy81NjUwNDkiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn19fX0.1oRBHqDYPJuaCKAZntxUBO13N6GDr4N2tInO9hnLgdMkREc7FVT5sOewkpMjbbK6G5wJa9FiCyLkpM1GyGw8_g"],"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-14T13:22:00.899433","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"authentication","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..XTARC4a3ERtWyWlqS-g-H_LLOomvlXQHcpLx4_TzPDwTTwyJ0jrEef2wQ7rZE4AZjV5krNHjAFhezO2U1odBtA"}}';
