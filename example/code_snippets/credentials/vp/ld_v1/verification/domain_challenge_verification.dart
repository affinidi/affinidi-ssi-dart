// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/suites/universal_presentation_verifier.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_domain_challenge_verifier.dart';

void main() async {
  // Parse the VP string into a VerifiablePresentation object
  final v1Vp = UniversalPresentationParser.parse(v1VpString);

  // create universal presentation verifier with custom domain and challenge verifier
  final domainVerifier = VpDomainChallengeVerifier(
      domain: ['test-domain'], challenge: 'test-challenge');
  final verifier =
      UniversalPresentationVerifier(customVerifiers: [domainVerifier]);
  final verificationStatus = await verifier.verify(v1Vp);

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
    '{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"testVpV1Id","type":["VerifiablePresentation"],"holder":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"holder":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"issuanceDate":"2025-11-17T13:42:17.628350Z","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-17T14:42:17.642651","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..WNI-EkxU41TtvGamWyZ6YplOLOfwKRB6wKO9uWqQ4zcKZ9-lX8eyrw8GKzABIRTY0CvZoIss-dFrfkuVDWR1Lw"}}],"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-17T14:42:47.887757","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"authentication","domain":"test-domain","challenge":"test-challenge","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..YYMKRFnStca0chR6xrdn9sR3UtW7CtRK8a7ZFfYV3TIHk-sYkRDgxo5r1TKp3GyI0KaktghygsPE0YVb6Pg8Kw"}}';
