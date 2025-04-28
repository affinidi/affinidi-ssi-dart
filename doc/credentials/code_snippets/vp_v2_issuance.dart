// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/ssi.dart';
import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v2_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v2/vp_data_model_v2.dart';

import 'did_signer.dart';

Future<void> main() async {
  // Deterministic seed for key generation
  final testSeed = Uint8List.fromList(
    utf8.encode('test seed for deterministic key generation'),
  );

  // Initialize signer from seed
  final signer = await initSigner(testSeed);

  // Load example credentials (LD VC V1 + LD VC V2 + SD-JWT V2)
  final ldV1VC = UniversalParser.parse((v1VcString));

  final ldV2VC = UniversalParser.parse((v2VcString));

  final sdjwtV2VC = UniversalParser.parse(jwtVcString);

  // Create a Verifiable Presentation (V2)
  final v2Vp = MutableVpDataModelV2(
      context: [VpDataModelV2.contextUrl],
      id: Uri.parse('testVpV2'),
      type: {'VerifiablePresentation'},
      verifiableCredential: [ldV1VC, ldV2VC, sdjwtV2VC]);

  // create a proof Generator
  final proofGenerator = Secp256k1Signature2019Generator(
    signer: signer,
  );

  // Issue the VP using the V2 suite
  final vpToSign = VpDataModelV2.fromJson(v2Vp.toJson());
  final issuedVp = await LdVpDm2Suite().issue(
      unsignedData: vpToSign,
      issuer: signer.did,
      proofGenerator: proofGenerator);

  // Output result
  print('Serialized VP:\n${issuedVp.serialized}');
}

const v1VcString =
    '{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"issuanceDate":"2025-04-22T11:23:37.513399","expirationDate":"2026-04-22T11:23:37.513400","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"holder":{"id":"did:example:1"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T11:23:37.514746","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..CcRHMEsMLurFKqpGlX7RwncS1e5GKwJPaKdJGeyK_yEoSiWJKekboeWnOcCuH3QJE-8rMsCdmcNmR1UyXucA_Q"}}';
const v2VcString =
    '{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"validFrom":"2025-04-22T11:40:21.359650","validUntil":"2026-04-22T11:40:21.359650","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T11:40:21.361346","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..wogMzfg-au-YTXTEZHv6uOiKYO7DxF4eAl1zoN1gwh5qk_OfvK4wniG3k0PiYA7jQZV-HBUBAdhCAhTbn3Zw3A"}}';

const jwtVcString =
    'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NoVTROQ1A5SG1jSGE0SE5rd0p6V2dXN0xlcG9jRWNDZ0h2Z0RmZUxxZ2dvVmYjelEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsInR5cCI6InNkK2p3dCJ9.eyJpYXQiOjE3NDQ2NDYwMDgsImlzcyI6ImRpZDprZXk6elEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsIm5iZiI6MTY3MjU3NDQwMCwiZXhwIjoxODMwMzQwODAwLCJzdWIiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIl0sImlzc3VlciI6ImRpZDprZXk6elEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpZCI6InVybjp1dWlkOjEyMzRhYmNkLTEyMzQtYWJjZC0xMjM0LWFiY2QxMjM0YWJjZCIsInZhbGlkRnJvbSI6IjIwMjMtMDEtMDFUMTI6MDA6MDAuMDAwWiIsInZhbGlkVW50aWwiOiIyMDI4LTAxLTAxVDEyOjAwOjAwLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsicnRXOFNIYUFtdy10b3dsOGh6b0p4cHBiaU1aLXNnWlI4S2k2VzVkNC1BayIsIlVKcFpDQzdfNGpJbkZKM0NuWXhRVkxsSmNNMHJjbmpHazloR3dnWWh1Y1kiXX0sIl9zZF9hbGciOiJzaGEtMjU2In0.INMg_DV9bZ4lPnmJd92f6ZqA6RXMLByhNh4Ta7i-Cj8ilmwpda4OfqdJu0ZS3uNKvQE0_enKy2YMbDrCbVs7mg~WyIyUVpNNnJHQWhOcjRBbTZMREoteTl3IiwiaWQiLCJkaWQ6ZXhhbXBsZTpzdWJqZWN0Il0=~WyJrUUtIVC1WZUMxdWVSLXVmNEZHN0tBIiwiZGVncmVlIix7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn1d~';
