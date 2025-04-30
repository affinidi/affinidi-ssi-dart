// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';

void main() {
  // Simulated VC JSON from fixture
  final credentialJson = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.affinidi.io/HITContactsV1R0.jsonld'
    ],
    'id': 'claimId:02-aaaaaa-aaaaaaaaaaa',
    'type': ['VerifiableCredential', 'HITContacts'],
    'holder': {
      'id': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa'
    },
    'credentialSubject': {'email': 'user@affinidi.com'},
    'credentialSchema': {
      'id': 'credentialSchemaId',
      'type': 'credentialSchemaType'
    },
    'issuanceDate': '2024-07-16T20:16:05.648',
    'expirationDate': '2024-07-18T20:16:05.648',
    'issuer': 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa',
    'proof': {
      'type': 'EcdsaSecp256k1Signature2019',
      'created': '2024-07-16T18:16:05Z',
      'proofPurpose': 'assertionMethod',
      'verificationMethod':
          'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa#aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa',
      'jws':
          'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..ee19g6fjm34kb9aG_tGzVyW5-sLq6KvFTBnmOHX3ibBFrikO8xYMp3pCg1SU3gePtSnAVKzyDIfxj1xifGcQHw'
    }
  };

  // Parse the VC from JSON
  final vc = VcDataModelV1.fromJson(credentialJson);

  // Print high-level properties
  print('VC ID: ${vc.id}');
  print('VC Types: ${vc.type}');
  print('VC Issuer: ${vc.issuer.id}');
  print('VC Subject: ${vc.credentialSubject.first.toJson()}');
  print('VC Valid From: ${vc.validFrom}');
  print('VC Valid Until: ${vc.validUntil}');
  print('VC Proof Type: ${vc.proof.first.type}');

  // Serialize back to JSON
  final serialized = vc.toJson();
  print('\nSerialized VC JSON:\n$serialized');
}
