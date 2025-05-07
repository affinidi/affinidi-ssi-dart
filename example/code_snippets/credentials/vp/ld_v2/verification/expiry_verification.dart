// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_expiry_verifier.dart';

void main() async {
  // Parse the VP string into a VerifiablePresentation object
  final v2Vp = UniversalPresentationParser.parse(v2VpString);

  // Create a VpExpiryVerifier with a mocked "now" time
  final verificationStatus =
      await VpExpiryVerifier(getNow: _getNow).verify(v2Vp);

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
    '{"@context":["https://www.w3.org/ns/credentials/v2"],"id":"testVpV2","type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.affinidi.com/EmailV1-0.jsonld"],"id":"claimId:2b249d9d93f38e3a","type":["VerifiableCredential","Email"],"credentialSchema":{"id":"https://schema.affinidi.com/EmailV1-0.json","type":"JsonSchemaValidator2018"},"credentialSubject":{"email":"savani.j+dev21@affinidi.com"},"holder":{"id":"did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf"},"issuanceDate":"2024-09-04T12:15:23.355Z","issuer":"did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6","proof":{"type":"EcdsaSecp256k1Signature2019","created":"2024-09-04T12:15:29Z","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6#zQ3shXLA2cHanJgCUsDfXxBi2BGnMLArHVz5NWoC9axr8pEy6","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..lN5GVttiM5den0qU1fcgc1QdCbHhmWgdI3iIp_VyprQtrzT9GK3eQyuT7-C1VBcD-AE7ZYWwdsMNcgsuUmH0Vg"}},{"@context":["https://www.w3.org/ns/credentials/v2","https://schema.affinidi.com/UserProfileV1-0.jsonld"],"issuer":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":["VerifiableCredential","UserProfile"],"id":"uuid:123456abcd","credentialSchema":{"id":"https://schema.affinidi.com/UserProfileV1-0.json","type":"JsonSchemaValidator2018"},"validFrom":"2025-04-22T11:40:21.359650","validUntil":"2026-04-22T11:40:21.359650","credentialSubject":{"Fname":"Fname","Lname":"Lame","Age":"22","Address":"Eihhornstr"},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","created":"2025-04-22T11:40:21.361346","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..wogMzfg-au-YTXTEZHv6uOiKYO7DxF4eAl1zoN1gwh5qk_OfvK4wniG3k0PiYA7jQZV-HBUBAdhCAhTbn3Zw3A"}},{"@context":["https://www.w3.org/ns/credentials/v2"],"id":"data:application/vc+sd-jwt,eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6a2V5OnpRM3NoVTROQ1A5SG1jSGE0SE5rd0p6V2dXN0xlcG9jRWNDZ0h2Z0RmZUxxZ2dvVmYjelEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsInR5cCI6InNkK2p3dCJ9.eyJpYXQiOjE3NDQ2NDYwMDgsImlzcyI6ImRpZDprZXk6elEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsIm5iZiI6MTY3MjU3NDQwMCwiZXhwIjoxODMwMzQwODAwLCJzdWIiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIl0sImlzc3VlciI6ImRpZDprZXk6elEzc2hVNE5DUDlIbWNIYTRITmt3SnpXZ1c3TGVwb2NFY0NnSHZnRGZlTHFnZ29WZiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpZCI6InVybjp1dWlkOjEyMzRhYmNkLTEyMzQtYWJjZC0xMjM0LWFiY2QxMjM0YWJjZCIsInZhbGlkRnJvbSI6IjIwMjMtMDEtMDFUMTI6MDA6MDAuMDAwWiIsInZhbGlkVW50aWwiOiIyMDI4LTAxLTAxVDEyOjAwOjAwLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsicnRXOFNIYUFtdy10b3dsOGh6b0p4cHBiaU1aLXNnWlI4S2k2VzVkNC1BayIsIlVKcFpDQzdfNGpJbkZKM0NuWXhRVkxsSmNNMHJjbmpHazloR3dnWWh1Y1kiXX0sIl9zZF9hbGciOiJzaGEtMjU2In0.INMg_DV9bZ4lPnmJd92f6ZqA6RXMLByhNh4Ta7i-Cj8ilmwpda4OfqdJu0ZS3uNKvQE0_enKy2YMbDrCbVs7mg~WyIyUVpNNnJHQWhOcjRBbTZMREoteTl3IiwiaWQiLCJkaWQ6ZXhhbXBsZTpzdWJqZWN0Il0=~WyJrUUtIVC1WZUMxdWVSLXVmNEZHN0tBIiwiZGVncmVlIix7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn1d~","type":["EnvelopedVerifiableCredential"]}],"holder":"did:key:zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf","proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"assertionMethod","verificationMethod":"did:key:zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf#zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf","created":"2025-04-22T11:46:12.346141","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..sWJ0v1SwiVuZwy_OBu4-GelLy6Ppqs_3Ac4nLc0oe4B5v6eXu7j-83bv2ihv01omjKo-rkCy6StcC1pX_RKHNw"}}';

DateTime _getNow() {
  return DateTime.parse('2025-04-25');
}
