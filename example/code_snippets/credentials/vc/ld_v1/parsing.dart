// ignore_for_file: avoid_print

import 'package:ssi/ssi.dart';

void main() {
  // Parse the credential
  final parsedVc = UniversalParser.parse(v1VcString);
  print('Parsed VC:\n${parsedVc.toJson()}');
}

// Example VC string
const v1VcString = r'''
  {
      "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld"
      ],
      "id": "uuid:123456abcd",
      "type": [
          "VerifiableCredential",
          "UserProfile"
      ],
      "credentialSubject": {
          "Fname": "Fname",
          "Lname": "Lame",
          "Age": "22",
          "Address": "Eihhornstr"
      },
      "credentialSchema": {
          "id": "https://schema.affinidi.com/UserProfileV1-0.json",
          "type": "JsonSchemaValidator2018"
      },
      "issuanceDate": "2023-01-01T09:51:00.272Z",
      "expirationDate": "3024-01-01T12:00:00Z",
      "issuer": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
      "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2025-04-11T15:20:35Z",
          "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jL90Nk1rSfgBXgZJif44x1KkdD0iYgkRjTfChEb0W0gJ6HDDc5BVE5jb1osse7JEueSSJcYaAMfbh_2QsOdcSA"
      }
  }
  ''';
