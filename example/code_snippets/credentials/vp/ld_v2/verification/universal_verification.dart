// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/credentials.dart';

void main() async {
  // Parse the VP string into a VerifiablePresentation object
  final v2Vp = UniversalPresentationParser.parse(v2VpString);

  // Verify using UniversalPresentationVerifier
  final verificationStatus = await UniversalPresentationVerifier().verify(v2Vp);

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
const v2VpString =
    '{"@context":["https://www.w3.org/ns/credentials/v2"],"id":"testVpV2","type":["VerifiablePresentation"],"holder":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"verifiableCredential":[{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":{"id":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1"},"type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-14T10:48:31.846533","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..hop2PsFf6es3IGK04o2J7VilM_3P2qsqzaBktaHniHEfKDPRpdTdoxmwwXkFPiAiPN9YNn95CjLmrllKIepFJA"}}],"proof":{"type":"EcdsaSecp256k1Signature2019","created":"2025-11-14T10:50:07.554302","verificationMethod":"did:key:zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1#zQ3sha56jgL3375utvumTafCFeLMMCRmvsggy6LYdaYsz1QJ1","proofPurpose":"authentication","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..EOPzIXCKl3b7P1e7S1p4gORoyAFnIISKgcm4tvKEj9xtSq65dXBCaH3tp_p273pyx56O9FvqpWzy2qyeFm6j1Q"}}';
