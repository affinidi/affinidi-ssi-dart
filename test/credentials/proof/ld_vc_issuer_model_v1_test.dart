import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  group('Test Linked Data VC issuance', () {
    test('Create and verify proof', () async {
      DidSigner signer = await _initSigner(seed);

      final unsignedCredential = MutableVcDataModelV1(
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
        EcdsaSecp256k1Signature2019CreateOptions(
          signer: signer,
        ),
      );

      unsignedCredential.proof = proof.toJson();

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
          customDocumentLoader: _testLoadDocument,
        ),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('CWE issued must verify', () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final verificationResult = await proofSuite.verifyProof(
        cweResponse as Map<String, dynamic>,
        EcdsaSecp256k1Signature2019VerifyOptions(
          customDocumentLoader: _testLoadDocument,
        ),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });
  });
}

Future<DidSigner> _initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final publicKey = await wallet.generateKey(Bip32Wallet.rootKeyId);
  final doc = await DidKey.create(publicKey);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    wallet: wallet,
    walletKeyId: Bip32Wallet.rootKeyId,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}

final cweResponse = jsonDecode(
  VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
);

final _userProfile = jsonDecode(r'''
{"@context":{"UserProfile":{"@id":"https://schema.affinidi.com/UserProfileV1-0.jsonld","@context":{"@version":1.1,"@protected":true}},"Fname":{"@id":"schema-id:Fname","@type":"https://schema.org/Text"},"Lname":{"@id":"schema-id:Lname","@type":"https://schema.org/Text"},"Age":{"@id":"schema-id:Age","@type":"https://schema.org/Text"},"Address":{"@id":"schema-id:Address","@type":"https://schema.org/Text"}}}
''');

Future<Map<String, dynamic>?> _testLoadDocument(Uri url) {
  if (url.toString() == 'https://schema.affinidi.com/UserProfileV1-0.jsonld') {
    return Future.value(_userProfile as Map<String, dynamic>);
  }
  return Future.value(null);
}
