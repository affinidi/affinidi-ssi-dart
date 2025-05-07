// ignore_for_file: avoid_print

import 'dart:typed_data';

import 'package:ssi/ssi.dart';

import '../../../did/did_signer.dart';

void main() async {
  // Parse the VC string
  final ldV2VC = UniversalParser.parse(v2VcString);

  // Deterministic seed for key generation
  final testSeed = Uint8List.fromList(List.generate(32, (index) => index + 1));

  // Initialize signer from seed
  final signer = await initSigner(testSeed);

  // Build the unsigned Verifiable Presentation
  final v2Vp = MutableVpDataModelV2(
      context: [dmV2ContextUrl],
      id: Uri.parse('testVpV2'),
      type: {'VerifiablePresentation'},
      holder: MutableHolder.uri(signer.did),
      verifiableCredential: [ldV2VC]);

  final proofGenerator = Secp256k1Signature2019Generator(
      signer: signer, domain: ['fun.com'], challenge: 'test-challenge');

// Issue the VP with the proof attached
  final issuedPresentation = await LdVpDm2Suite().issue(
      unsignedData: VpDataModelV2.fromMutable(v2Vp),
      proofGenerator: proofGenerator);

  final verificationStatus = await VpDomainChallengeVerifier(
          domain: ['fun.com'], challenge: 'test-challenge')
      .verify(issuedPresentation);

  // Print results
  print('Is VP valid? ${verificationStatus.isValid}');
  if (!verificationStatus.isValid) {
    print('Errors: ${verificationStatus.errors}');
  }
  if (verificationStatus.warnings.isNotEmpty) {
    print('Warnings: ${verificationStatus.warnings}');
  }
}

// Example VC string
const v2VcString =
    '{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"validFrom":"2025-04-22T10:14:50.323952","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T10:14:50.325530","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..8zzMdjUNQSpoh6hd-IOYtxxuD45MAd0ZNgqyiUJMKWMbkTqYQTxouzNMGTnFfRY8wMxt9VYgV-vBWb-99iDniw"}}';
