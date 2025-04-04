import 'dart:convert';

import 'dart:typed_data';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/issuance/ldp_vc_issuer_model_v1.dart';
import 'package:ssi/src/credentials/models/vc_data_model_v1.dart';
import 'package:ssi/src/did/did_signer.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  group('Test ldp VC issuance', () {
    test('the main did key should match to the expected value', () async {
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
        credentialSchema: [
          CredentialSchema.fromJson({
            "id": "https://schema.affinidi.com/UserProfileV1-0.json",
            "type": "JsonSchemaValidator2018"
          })
        ],
        issuanceDate: DateTime.parse("2023-01-01T09:51:00.272Z"),
        issuer: "did:key:zQ3shtijsLSQoFxN4gXcX8C6ZTJBrDpCTugray7sSP4BamFWT",
      );

      await LdpVcdm1Issuer.issue(
        unsignedCredential: unsignedCredential,
        signer: signer,
      );
    });
  });
}

Future<DidSigner> _initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final keyPair = await wallet.createKeyPair("0-0");
  final doc = await DidKey.create([keyPair]);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: "0-0",
    keyPair: keyPair,
    signatureScheme: SignatureScheme.es256k,
  );
  return signer;
}

final cweResponse = jsonDecode(r'''
{
    "signedCredential": {
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
}
''');
