// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_integrity_verifier.dart';

void main() async {
  // Parse the VP string into a VerifiablePresentation object
  final v1Vp = UniversalPresentationParser.parse(v1VpString);

  // Create a VpIntegrityVerifier
  final verificationStatus = await VpIntegrityVerifier().verify(v1Vp);

  // Print results
  print("Is VP valid? ${verificationStatus.isValid}");
  if (!verificationStatus.isValid) {
    print("Errors: ${verificationStatus.errors}");
  }
  if (verificationStatus.warnings.isNotEmpty) {
    print("Warnings: ${verificationStatus.warnings}");
  }
}

// Example VP string
const v1VpString =
    '{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"testVpV1","type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"issuanceDate":"2025-04-22T11:23:37.513399","expirationDate":"2026-04-22T11:23:37.513400","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"holder":{"id":"did:example:1"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T11:23:37.514746","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..CcRHMEsMLurFKqpGlX7RwncS1e5GKwJPaKdJGeyK_yEoSiWJKekboeWnOcCuH3QJE-8rMsCdmcNmR1UyXucA_Q"}},"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NodDFaODU4d2hwVlFCdzJjSFBXZ3F2UzhNeHlSS05zZGpvWlJGWjJZM2hyVGgjelEzc2h0MVo4NTh3aHBWUUJ3MmNIUFdncXZTOE14eVJLTnNkam9aUkZaMlkzaHJUaCIsInR5cCI6IkpXVCJ9.eyJuYmYiOjEyNjIzMDQwMDAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvaXNzdWVycy81NjUwNDkiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn19fX0.1oRBHqDYPJuaCKAZntxUBO13N6GDr4N2tInO9hnLgdMkREc7FVT5sOewkpMjbbK6G5wJa9FiCyLkpM1GyGw8_g"],"holder":"did:key:zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf","proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf#zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf","created":"2025-04-22T11:24:55.089845","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..Pg-icstiVFiB9re44QyfUIgb1ACG_hDub2VgRluApII_3mqsSTR4UaN-V0_DmmlvZaG2GXfQlUTJamL8hgMOSQ"}}';
