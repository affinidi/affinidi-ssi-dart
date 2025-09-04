import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('LD Credential v2 Validation Tests', () {
    final testSeed = Uint8List.fromList(
        utf8.encode('test seed for deterministic key generation'));

    late DidSigner signer;
    late Secp256k1Signature2019Generator signerAdapter;
    late LdVcDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      signerAdapter = Secp256k1Signature2019Generator(signer: signer);
      suite = LdVcDm2Suite();
    });

    test('Throws when context is empty', () {
      final credentialWithEmptyContext = MutableVcDataModelV2(
        MutableVcDataModelV1.fromJson([]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV2.fromMutable(credentialWithEmptyContext),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when context does not include required URL', () {
      final credentialWithWrongContext = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson(['https://www.w3.org/2018/credentials/v1']),
        // Wrong context URL
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV2.fromMutable(credentialWithWrongContext),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when type is empty', () {
      final credentialWithEmptyType = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV2.fromMutable(credentialWithEmptyType),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when issuer is empty', () {
      final credentialWithEmptyIssuer = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri(''),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credentialWithEmptyIssuer),
          proofGenerator: signerAdapter,
        ),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when credentialSubject is empty', () {
      final credentialWithEmptySubject = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [],
      );

      expect(
        () => VcDataModelV2.fromMutable(credentialWithEmptySubject),
        throwsA(isA<SsiException>()),
      );
    });

    test('Reports multiple validation errors at once', () {
      final credentialWithMultipleErrors = MutableVcDataModelV2(
        MutableVcDataModelV1.fromJson([]),
        issuer: MutableIssuer.uri(''),
        type: {},
        credentialSubject: [],
      );

      expect(
        () => VcDataModelV2.fromMutable(credentialWithMultipleErrors),
        throwsA(isA<SsiException>()),
      );
    });
  });
}

Future<DidSigner> initSigner(Uint8List seed) async {
  // Ensure seed is 32 bytes (256 bits) by hashing it
  final hashedSeed = sha256.convert(seed).bytes;
  final wallet = Bip32Wallet.fromSeed(Uint8List.fromList(hashedSeed));
  final keyPair = await wallet.generateKey(keyId: "m/0'/0'");
  final doc = DidKey.generateDocument(keyPair.publicKey);

  final signer = DidSigner(
    did: doc.id,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: keyPair,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
