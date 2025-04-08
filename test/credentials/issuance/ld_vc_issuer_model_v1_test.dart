import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/issuance/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  group('Test Linked Data VC issuance', () {
    test('Create and verify proof', () async {
      DidSigner signer = await _initSigner(seed);

      final unsignedCredential = VcDataModelV1(
        context: [
          "https://www.w3.org/2018/credentials/v1",
          "https://schema.affinidi.com/UserProfileV1-0.jsonld"
        ],
        id: "uuid:123456abcd",
        type: ["VerifiableCredential", "UserProfile"],
        credentialSubject: {
          "Fname": "Fname",
          "Lname": "Lame",
          "Age": "22",
          "Address": "Eihhornstr"
        },
        holder: {
          "id": "did:example:1",
        },
        credentialSchema: [
          CredentialSchema.fromJson({
            "id": "https://schema.affinidi.com/UserProfileV1-0.json",
            "type": "JsonSchemaValidator2018"
          })
        ],
        issuanceDate: DateTime.now(),
        issuer: signer.did,
      );

      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019Options(signer: signer),
      );

      unsignedCredential.proof = proof.toJson();

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.issues, isEmpty);
    });

    test('CWE issued must verify', () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final verificationResult = await proofSuite.verifyProof(
        cweResponse,
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.issues, isEmpty);
    });
  });
}

Future<DidSigner> _initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final keyPair = await wallet.createKeyPair("0-0");
  final doc = await DidKey.create([keyPair]);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: keyPair,
    signatureScheme: SignatureScheme.ecdsa_secp256r1_sha256,
  );
  return signer;
}

final cweResponse = jsonDecode(r'''
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
  "credentialSchema": [
      {
          "id": "https://schema.affinidi.com/UserProfileV1-0.json",
          "type": "JsonSchemaValidator2018"
      }
  ],
  "issuanceDate": "2023-01-01T09:51:00.272Z",
  "issuer": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
  "proof": {
      "type": "EcdsaSecp256k1Signature2019",
      "created": "2025-04-03T18:25:33Z",
      "verificationMethod": "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT#zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
      "proofPurpose": "assertionMethod",
      "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..F91qwvm_WdbWUAkQx8qSiCxyjyDV2N1nM0qAycnh67Rahe8hTxf0hR9Mi-SheY4DBKUxefXjUiG0RvpIl3h8tQ"
  }
}
''');
