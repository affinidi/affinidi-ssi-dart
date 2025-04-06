import 'dart:convert';

import 'dart:typed_data';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/issuance/ldp_vc_issuer_model_v1.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
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
        holder: {
          "id": "did:example:1",
        },
        credentialSchema: [
          CredentialSchema.fromJson({
            "id": "https://schema.affinidi.com/UserProfileV1-0.json",
            "type": "JsonSchemaValidator2018"
          })
        ],
        issuanceDate: DateTime.parse("2023-01-01T09:51:00.272Z"),
        issuer:
            "did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ;elem:initial-state=eyJwcm90ZWN0ZWQiOiJleUp2Y0dWeVlYUnBiMjRpT2lKamNtVmhkR1VpTENKcmFXUWlPaUlqY0hKcGJXRnllU0lzSW1Gc1p5STZJa1ZUTWpVMlN5SjkiLCJwYXlsb2FkIjoiZXlKQVkyOXVkR1Y0ZENJNkltaDBkSEJ6T2k4dmR6TnBaQzV2Y21jdmMyVmpkWEpwZEhrdmRqSWlMQ0p3ZFdKc2FXTkxaWGtpT2x0N0ltbGtJam9pSTNCeWFXMWhjbmtpTENKMWMyRm5aU0k2SW5OcFoyNXBibWNpTENKMGVYQmxJam9pVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T0NJc0luQjFZbXhwWTB0bGVVaGxlQ0k2SWpBeVl6QTBaR00yTUdRME1UWmtaRFl3TkdJNVlUQTJaV0l3WkRObE5USTNOVEpsT1RNM1pXSXpabVUwTmpRMlpUQXdOV1ZqTnpjd1l6YzJObUl4TWpBNU5pSjlMSHNpYVdRaU9pSWpjbVZqYjNabGNua2lMQ0oxYzJGblpTSTZJbkpsWTI5MlpYSjVJaXdpZEhsd1pTSTZJbE5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGdpTENKd2RXSnNhV05MWlhsSVpYZ2lPaUl3TXpKaU5ETmpZV0ZtTkRBellXTmxOV0ZtTWpBd1ptSmlPRGxsWm1Oa1pEYzJNVEF4TWpSak5UUXpZVFEwT1dNMU1USTBNelUzTWprd1lURmtOalU0TVRZaWZWMHNJbUYxZEdobGJuUnBZMkYwYVc5dUlqcGJJaU53Y21sdFlYSjVJbDBzSW1GemMyVnlkR2x2YmsxbGRHaHZaQ0k2V3lJamNISnBiV0Z5ZVNKZGZRIiwic2lnbmF0dXJlIjoiRWVlaGxnajdjVnA0N0dHRXBUNEZieFV1WG1VY1dXZktHQkI2aUxnQTgtd3BLcXViSHVEeVJYQzQ4SldMMjZQRzVZV0xtZFRwcV8wVHNkVmhVMlEwYUEifQ",
      );

      final credential = await LdpVcdm1Issuer.issue(
        unsignedCredential: unsignedCredential,
        signer: signer,
      );

      print("------------------------");
      print(jsonEncode(credential.toJson()));
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
