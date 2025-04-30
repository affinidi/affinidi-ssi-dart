// ignore_for_file: avoid_print
import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/suites/universal_presentation_verifier.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_domain_challenge_verifier.dart';

import 'vp_expiry_verification.dart';

void main() async {
  // Parse the VP string into a VerifiablePresentation object
  final v1Vp = UniversalPresentationParser.parse(v2VpString);

  // create universal presentation verifier with custom domain and challenge verifier
  final domainVerifier = VpDomainChallengeVerifier(
      domain: ['fun.com'], challenge: 'test-challenge');
  final verifier =
      UniversalPresentationVerifier(customVerifiers: [domainVerifier]);
  final verificationStatus = await verifier.verify(v1Vp);

  // Print results
  print("Is VP valid? ${verificationStatus.isValid}");
  if (!verificationStatus.isValid) {
    print("Errors: ${verificationStatus.errors}");
  }
  if (verificationStatus.warnings.isNotEmpty) {
    print("Warnings: ${verificationStatus.warnings}");
  }
}

// Example VP sting with domain and challenge
const v1VpString =
    '{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"testVpV1","type":["VerifiablePresentation"],"holder":"did:key:zQ3shX6mwJADbt9LwKhcmvZ9BkqjJiyNN4VPk8jdH95QX2Yn5","verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/EmailV1-0.jsonld"],"id":"claimId:2b249d9d93f38e3a","type":["VerifiableCredential","Email"],"credentialSchema":{"id":"https://schema.affinidi.com/EmailV1-0.json","type":"JsonSchemaValidator2018"},"credentialSubject":{"email":"savani.j+dev21@affinidi.com"},"holder":{"id":"did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf"},"issuanceDate":"2024-09-04T12:15:23.355Z","issuer":"did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6","proof":{"type":"EcdsaSecp256k1Signature2019","created":"2024-09-04T12:15:29Z","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6#zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..lN5GVttiM5den0qU1fcgc1QdCbHhmWgdI3iIp_VyprQtrzT9GK3eQyuT7-C1VBcD-AE7ZYWwdsMNcgsuUmH0Vg"}}],"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-04-28T19:54:52.743226","verificationMethod":"did:key:zQ3shX6mwJADbt9LwKhcmvZ9BkqjJiyNN4VPk8jdH95QX2Yn5#zQ3shX6mwJADbt9LwKhcmvZ9BkqjJiyNN4VPk8jdH95QX2Yn5","proofPurpose":"assertionMethod","domain":"fun.com","challenge":"test-challenge","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..4fbFj0t1RLe0hzqrqCFLCNTFaxgvurLFAtdtJSCI96RPF4oF2jehoUX1P3p3REbCCXrOvogsYf7fphq_2aLaMA"}}';
