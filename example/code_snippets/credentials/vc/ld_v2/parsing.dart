// ignore_for_file: avoid_print

import 'package:ssi/ssi.dart';

void main() {
  // Parse the credential
  final parsedVc = UniversalParser.parse(v2VcString);
  print('Parsed VC:\n${parsedVc.toJson()}');
}

// Example VC string
const v2VcString =
    '{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"validFrom":"2025-04-22T10:14:50.323952","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T10:14:50.325530","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..8zzMdjUNQSpoh6hd-IOYtxxuD45MAd0ZNgqyiUJMKWMbkTqYQTxouzNMGTnFfRY8wMxt9VYgV-vBWb-99iDniw"}}';
