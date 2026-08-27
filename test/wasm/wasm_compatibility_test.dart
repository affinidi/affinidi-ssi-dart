import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

final _seed = Uint8List.fromList(
  List<int>.generate(32, (index) => index + 1),
);
final _payload = Uint8List.fromList([1, 2, 3, 4]);
final _profileContextUri = Uri.parse('https://example.com/profile/v1');

Future<Map<String, dynamic>?> _loadDocument(Uri uri) async {
  if (uri != _profileContextUri) return null;

  return {
    '@context': {
      '@version': 1.1,
      'name': 'https://schema.org/name',
    },
  };
}

void main() {
  group('When running supported SSI operations in WebAssembly', () {
    test('it creates a DID and performs cryptographic operations', () async {
      final keyPair = Secp256k1KeyPair.fromSeed(_seed);

      final didDocument = DidKey.generateDocument(keyPair.publicKey);
      final signature = await keyPair.sign(_payload);
      final encrypted = await keyPair.encrypt(_payload);

      expect(didDocument.id.toString(), startsWith('did:key:'));
      expect(await keyPair.verify(_payload, signature), isTrue);
      expect(await keyPair.decrypt(encrypted), _payload);
    });

    test('it issues and verifies a JWT verifiable credential', () async {
      final keyPair = Secp256k1KeyPair.fromSeed(_seed);
      final didDocument = DidKey.generateDocument(keyPair.publicKey);
      final signer = DidSigner(
        did: didDocument.id,
        didKeyId: didDocument.verificationMethod.first.id,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
      );
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:wasm-jwt-credential',
        'type': ['VerifiableCredential', 'WasmCredential'],
        'issuanceDate': '2026-01-01T00:00:00Z',
        'credentialSubject': {
          'id': 'did:example:holder',
          'name': 'Wasm Holder',
        },
      })
        ..issuer = MutableIssuer.uri(signer.did);
      final suite = JwtDm1Suite();

      final issued = await suite.issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        signer: signer,
      );
      final parsed = suite.parse(issued.serialized);

      expect(await suite.verifyIntegrity(parsed), isTrue);
    });

    test('it issues and verifies a data-integrity credential', () async {
      final keyPair = P256KeyPair.fromSeed(_seed);
      final didDocument = DidKey.generateDocument(keyPair.publicKey);
      final signer = DidSigner(
        did: didDocument.id,
        didKeyId: didDocument.verificationMethod.first.id,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_p256_sha256,
      );
      final credential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          dmV1ContextUrl,
          'https://w3id.org/security/data-integrity/v2',
          _profileContextUri.toString(),
        ]),
        id: Uri.parse('urn:uuid:wasm-data-integrity-credential'),
        type: {'VerifiableCredential', 'WasmCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:holder',
            'name': 'Wasm Holder',
          }),
        ],
        issuanceDate: DateTime.utc(2026),
        issuer: Issuer.uri(signer.did),
      );
      final generator = DataIntegrityEcdsaRdfcGenerator(
        signer: signer,
        customDocumentLoader: _loadDocument,
      );
      final verifier = DataIntegrityEcdsaRdfcVerifier(
        issuerDid: signer.did,
        customDocumentLoader: _loadDocument,
      );

      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        proofGenerator: generator,
      );
      final result = await verifier.verify(issued.toJson());

      expect(result.isValid, isTrue, reason: result.errors.join(', '));
    });

    test('it issues and verifies an SD-JWT verifiable credential', () async {
      final keyPair = Secp256k1KeyPair.fromSeed(_seed);
      final didDocument = DidKey.generateDocument(keyPair.publicKey);
      final signer = DidSigner(
        did: didDocument.id,
        didKeyId: didDocument.verificationMethod.first.id,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
      );
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:wasm-sd-jwt-credential'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'WasmCredential'},
        validFrom: DateTime.utc(2026),
        validUntil: DateTime.utc(2027),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:holder',
            'name': 'Wasm Holder',
          }),
        ],
      );
      final suite = SdJwtDm2Suite();

      final issued = await suite.issue(
        unsignedData: VcDataModelV2.fromMutable(credential),
        signer: signer,
      );
      final parsed = suite.parse(issued.serialized);

      expect(issued.serialized, contains('~'));
      expect(
        await suite.verifyIntegrity(
          parsed,
          getNow: () => DateTime.utc(2026, 6),
        ),
        isTrue,
      );
    });

    final keyPairs = <String, Future<KeyPair> Function()>{
      'secp256k1': () async => Secp256k1KeyPair.fromSeed(_seed),
      'P-256': () async => P256KeyPair.fromSeed(_seed),
      'P-384': () async => P384KeyPair.fromSeed(_seed),
      'P-521': () async => P521KeyPair.generate().$1,
      'ML-DSA-44': () async => (await MlDsa44KeyPair.fromSeed(_seed)).$1,
    };

    for (final MapEntry(key: algorithm, value: createKeyPair)
        in keyPairs.entries) {
      test('it signs and verifies with $algorithm', () async {
        final keyPair = await createKeyPair();
        final signature = await keyPair.sign(_payload);

        expect(await keyPair.verify(_payload, signature), isTrue);
      });
    }

    final generatedKeyPairs = <String, KeyPair Function()>{
      'secp256k1': () => Secp256k1KeyPair.generate().$1,
      'P-256': () => P256KeyPair.generate().$1,
      'P-384': () => P384KeyPair.generate().$1,
      'P-521': () => P521KeyPair.generate().$1,
      'ML-DSA-44': () => MlDsa44KeyPair.generate().$1,
    };

    for (final MapEntry(key: algorithm, value: generateKeyPair)
        in generatedKeyPairs.entries) {
      test('it securely generates a key pair for $algorithm', () {
        expect(generateKeyPair().publicKey.bytes, isNotEmpty);
      });
    }

    for (final MapEntry(key: algorithm, value: generateKeyPair)
        in generatedKeyPairs.entries.where(
      (entry) => entry.key != 'ML-DSA-44',
    )) {
      test('it encrypts and decrypts with $algorithm', () async {
        final keyPair = generateKeyPair();

        final encrypted = await keyPair.encrypt(_payload);

        expect(await keyPair.decrypt(encrypted), _payload);
      });
    }

    test('it explicitly rejects encryption with ML-DSA-44', () {
      final keyPair = MlDsa44KeyPair.generate().$1;

      expect(
        () => keyPair.encrypt(_payload),
        throwsA(isA<SsiException>()),
      );
    });
  });
}
