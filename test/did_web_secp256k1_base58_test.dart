import 'package:base_codecs/base_codecs.dart';

import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  test('did:web + secp256k1 + publicKeyBase58 should work', () async {
    // Generate a secp256k1 key pair
    final (keyPair, _) = Secp256k1KeyPair.generate();
    final publicKeyBase58 = base58BitcoinEncode(keyPair.publicKey.bytes);

    // Setup did:web identity
    final did = 'did:web:example.org';
    final vmId = '$did#key-1';

    // Create DID document with publicKeyBase58 (non-standard but widely used)
    final didDocument = DidDocument.fromJson({
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1-2019/v1'
      ],
      'id': did,
      'verificationMethod': [
        {
          'id': vmId,
          'type': 'EcdsaSecp256k1VerificationKey2019',
          'controller': did,
          'publicKeyBase58': publicKeyBase58,
        }
      ],
      'authentication': [vmId],
      'assertionMethod': [vmId]
    });

    // Verify the verification method was parsed correctly
    expect(didDocument.verificationMethod.length, 1);
    final vm = didDocument.verificationMethod.first;
    expect(vm, isA<VerificationMethodBase58>());
    expect(vm.type, 'EcdsaSecp256k1VerificationKey2019');

    // Create unsigned credential
    final unsignedVC = MutableVcDataModelV1(
      context: MutableJsonLdContext.fromJson([
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/2018/credentials/examples/v1'
      ]),
      id: Uri.parse('uuid:123456abcd'),
      type: {'VerifiableCredential'},
      credentialSubject: [
        MutableCredentialSubject({'id': did, 'name': 'Test User'})
      ],
      issuanceDate: DateTime.parse('2020-01-01T00:00:00Z'),
      issuer: Issuer.uri(did),
    );

    // Sign the credential
    final signer = DidSigner(
      did: did,
      didKeyId: vmId,
      keyPair: keyPair,
      signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
    );

    final generator = Secp256k1Signature2019Generator(
      signer: signer,
    );

    final issuedVC = await LdVcDm1Suite().issue(
      unsignedData: VcDataModelV1.fromMutable(unsignedVC),
      proofGenerator: generator,
    );

    // Verify the proof was created
    expect(issuedVC.toJson()['proof'], isNotNull);
    expect(issuedVC.toJson()['proof']['type'], 'EcdsaSecp256k1Signature2019');

    // Verify the credential with custom DID resolver
    final didResolver = TestDidResolver(didDocument);
    final verifier = Secp256k1Signature2019Verifier(
      issuerDid: did,
      didResolver: didResolver,
    );

    final result = await verifier.verify(issuedVC.toJson());

    expect(result.isValid, true, reason: 'Verification should succeed');
    expect(result.errors, isEmpty);
  });
}

/// Simple DID resolver for testing
class TestDidResolver implements DidResolver {
  final DidDocument _didDocument;

  TestDidResolver(this._didDocument);

  @override
  Future<DidDocument> resolveDid(String did) async {
    if (did == _didDocument.id) {
      return _didDocument;
    }
    throw Exception('DID not found: $did');
  }
}
