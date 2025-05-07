// ignore_for_file: avoid_print

import 'package:ssi/ssi.dart';

void main() async {
  // Parse the credential
  final verifiableCredential = UniversalParser.parse(vcString);

  // Run the integrity verifier
  final verifier = VcIntegrityVerifier();
  final result = await verifier.verify(verifiableCredential);

  // Print results
  print('Integrity verification result: ${result.isValid}');
  if (!result.isValid) {
    print('Errors: ${result.errors}');
  }
  if (result.warnings.isNotEmpty) {
    print('Warnings: ${result.warnings}');
  }
}

// Example VC string
const vcString = r'''
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://schema.affinidi.com/UserProfileV1-0.jsonld"
    ],
    "issuer": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
    "type": [
        "VerifiableCredential",
        "UserProfile"
    ],
    "id": "uuid:123456abcd",
    "credentialSchema": {
        "id": "https://schema.affinidi.com/UserProfileV1-0.json",
        "type": "JsonSchemaValidator2018"
    },
    "validFrom": "2025-04-22T11:40:21.359650",
    "validUntil": "2026-04-22T11:40:21.359650",
    "credentialSubject": {
        "Fname": "Fname",
        "Lname": "Lame",
        "Age": "22",
        "Address": "Eihhornstr"
    },
    "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2",
        "created": "2025-04-22T11:40:21.361346",
        "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..wogMzfg-au-YTXTEZHv6uOiKYO7DxF4eAl1zoN1gwh5qk_OfvK4wniG3k0PiYA7jQZV-HBUBAdhCAhTbn3Zw3A"
    }
}
''';
