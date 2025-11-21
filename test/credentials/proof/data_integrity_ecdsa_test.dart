import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final signer = await initP256Signer(seed);
  final p384Signer = await initP384Signer(seed);
  final edSigner = await initEdSigner(seed);

  group('Test Data Integrity ECDSA VC issuance', () {
    final multiBaseList = [MultiBase.base58bitcoin, MultiBase.base64UrlNoPad];

    for (final proofValueMultiBase in multiBaseList) {
      group(proofValueMultiBase.name, () {
        test('Create and verify Data Integrity ECDSA proof', () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/security/data-integrity/v2',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:123456abcd'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({
                'Fname': 'Fname',
                'Lname': 'Lame',
                'Age': '22',
                'Address': 'Eihhornstr'
              })
            ],
            holder: MutableHolder.uri('did:example:1'),
            credentialSchema: [
              MutableCredentialSchema(
                  id: Uri.parse(
                      'https://schema.affinidi.com/UserProfileV1-0.json'),
                  type: 'JsonSchemaValidator2018')
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
            signer: signer,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final proofVerifier =
              DataIntegrityEcdsaRdfcVerifier(issuerDid: signer.did);

          final verificationResult =
              await proofVerifier.verify(issuedCredential.toJson());

          expect(verificationResult.isValid, true);
          expect(verificationResult.errors, isEmpty);
          expect(verificationResult.warnings, isEmpty);

          final proof =
              issuedCredential.toJson()['proof'] as Map<String, dynamic>;
          expect(proof['type'], 'DataIntegrityProof');
          expect(proof['cryptosuite'], 'ecdsa-rdfc-2019');
          expect(proof['proofValue'], isNotNull);
          expect(proof['nonce'], isNotNull);

          final proofValueHeader = proof['proofValue'][0];
          expect(proofValueHeader,
              proofValueMultiBase == MultiBase.base58bitcoin ? 'z' : 'u');
        });

        test('Verification fails when nonce is tampered with after issuance',
            () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/security/data-integrity/v2',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:123456abcd'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({
                'Fname': 'Fname',
                'Lname': 'Lame',
                'Age': '22',
                'Address': 'Eihhornstr'
              })
            ],
            holder: MutableHolder.uri('did:example:1'),
            credentialSchema: [
              MutableCredentialSchema(
                  id: Uri.parse(
                      'https://schema.affinidi.com/UserProfileV1-0.json'),
                  type: 'JsonSchemaValidator2018')
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
            signer: signer,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          // Tamper with nonce to test verification
          final credential = issuedCredential.toJson();

          // Update the nonce to make sure that it's part of the signature
          credential['proof']['nonce'] = 'tampered-nonce-value';

          final proofVerifier =
              DataIntegrityEcdsaRdfcVerifier(issuerDid: signer.did);

          final verificationResult = await proofVerifier.verify(credential);

          // Verification should FAIL because nonce was tampered with
          expect(verificationResult.isValid, false);
          expect(verificationResult.errors, isNotEmpty);
          expect(
              verificationResult.errors.first, contains('signature invalid'));
        });

        test(
            'Create and verify Data Integrity ECDSA proof with data-integrity context',
            () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/security/data-integrity/v2',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:dataintegrityecdsa'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({
                'Fname': 'Fname',
                'Lname': 'Lame',
                'Age': '22',
                'Address': 'Eihhornstr'
              })
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
            signer: signer,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final proofVerifier =
              DataIntegrityEcdsaRdfcVerifier(issuerDid: signer.did);
          final verificationResult =
              await proofVerifier.verify(issuedCredential.toJson());

          expect(verificationResult.isValid, true);
          expect(verificationResult.errors, isEmpty);
        });

        test('Reject issuance without data-integrity or VC v2 context',
            () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              // Intentionally omit data-integrity and VC v2 contexts
              'https://www.w3.org/2018/credentials/v1',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:missingctx123'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({'Fname': 'Fname'}),
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
            signer: signer,
            proofValueMultiBase: proofValueMultiBase,
          );

          expect(
            () async => await LdVcDm1Suite().issue(
              unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
              proofGenerator: proofGenerator,
            ),
            throwsA(isA<SsiException>().having(
                (e) => e.code, 'code', SsiExceptionType.invalidContext.code)),
          );
        });

        test('Verify Data Integrity ECDSA proof through LdBaseSuite', () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              'https://www.w3.org/2018/credentials/v1',
              'https://w3id.org/security/data-integrity/v2',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:123456abcd'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({
                'Fname': 'Fname',
                'Lname': 'Lame',
                'Age': '22',
                'Address': 'Eihhornstr'
              })
            ],
            holder: MutableHolder.uri('did:example:1'),
            credentialSchema: [
              MutableCredentialSchema(
                  id: Uri.parse(
                      'https://schema.affinidi.com/UserProfileV1-0.json'),
                  type: 'JsonSchemaValidator2018')
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
            signer: signer,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final validationResult =
              await LdVcDm1Suite().verifyIntegrity(issuedCredential);

          final proof =
              issuedCredential.toJson()['proof'] as Map<String, dynamic>;
          final proofValueHeader = proof['proofValue'][0];

          expect(validationResult, true);
          expect(proofValueHeader,
              proofValueMultiBase == MultiBase.base58bitcoin ? 'z' : 'u');
        });
      });
    }
  });

  group('Test Data Integrity ECDSA-JCS VC issuance', () {
    test('Reject JCS issuance without data-integrity or VC v2 context',
        () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          // Intentionally omit data-integrity and VC v2 contexts
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:missingctxjcs256'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({'Fname': 'Fname'}),
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      expect(
        () async => await LdVcDm1Suite().issue(
          unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator,
        ),
        throwsA(isA<SsiException>().having(
            (e) => e.code, 'code', SsiExceptionType.invalidContext.code)),
      );
    });

    test('Create and verify Data Integrity ECDSA-JCS proof with P-256',
        () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        holder: MutableHolder.uri('did:example:1'),
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier =
          DataIntegrityEcdsaJcsVerifier(verifierDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);

      final proof = issuedCredential.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'ecdsa-jcs-2019');
      expect(proof['proofValue'], isNotNull);
      expect(proof['proofValue'], startsWith('z')); // base58-btc multibase
    });

    test('Create and verify Data Integrity ECDSA-JCS proof with P-384',
        () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        holder: MutableHolder.uri('did:example:1'),
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(p384Signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: p384Signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier =
          DataIntegrityEcdsaJcsVerifier(verifierDid: p384Signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);

      final proof = issuedCredential.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'ecdsa-jcs-2019');
      expect(proof['proofValue'], isNotNull);
      expect(proof['proofValue'], startsWith('z')); // base58-btc multibase
    });

    test(
        'Create and verify Data Integrity ECDSA-JCS proof with data-integrity context',
        () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:dataintegrityecdsajcs'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier =
          DataIntegrityEcdsaJcsVerifier(verifierDid: signer.did);
      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('JCS context validation works correctly', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({'name': 'Test User'})
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      // Verify that the proof contains the same @context as the document
      final credentialJson = issuedCredential.toJson();
      final proof = credentialJson['proof'] as Map<String, dynamic>;

      expect(proof.containsKey('@context'), true);

      final proofVerifier =
          DataIntegrityEcdsaJcsVerifier(verifierDid: signer.did);
      final verificationResult = await proofVerifier.verify(credentialJson);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
    });

    test('ECDSA-JCS rejects unsupported signature schemes', () {
      expect(
        () => DataIntegrityEcdsaJcsGenerator(signer: edSigner),
        throwsA(isA<SsiException>()),
      );
    });

    test('Verify Data Integrity ECDSA-JCS proof through LdBaseSuite', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        holder: MutableHolder.uri('did:example:1'),
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final validationResult =
          await LdVcDm1Suite().verifyIntegrity(issuedCredential);

      expect(validationResult, true);
    });
  });

  group('Test Data Integrity ECDSA-RDFC with did:web', () {
    test('Create and verify RDFC proof with did:web and P-256', () async {
      // Generate a P-256 key pair
      final (keyPair, _) = P256KeyPair.generate();

      // Setup did:web identity
      final did = 'did:web:example.org';
      final vmId = '$did#key-1';

      // Create DID document
      final didDocument = DidDocument.fromJson({
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1'
        ],
        'id': did,
        'verificationMethod': [
          {
            'id': vmId,
            'type': 'JsonWebKey2020',
            'controller': did,
            'publicKeyJwk': _publicKeyToJwk(keyPair.publicKey),
          }
        ],
        'authentication': [vmId],
        'assertionMethod': [vmId]
      });

      // Create unsigned credential
      final unsignedVC = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'John',
            'Lname': 'Doe',
          })
        ],
        issuanceDate: DateTime.parse('2020-01-01T00:00:00Z'),
        issuer: Issuer.uri(did),
      );

      // Sign the credential
      final signer = DidSigner(
        did: did,
        didKeyId: vmId,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_p256_sha256,
      );

      final generator = DataIntegrityEcdsaRdfcGenerator(
        signer: signer,
      );

      final issuedVC = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedVC),
        proofGenerator: generator,
      );

      // Verify the credential with custom DID resolver
      final didResolver = _TestDidResolver(didDocument);
      final verifier = DataIntegrityEcdsaRdfcVerifier(
          issuerDid: did, didResolver: didResolver);

      final result = await verifier.verify(issuedVC.toJson());

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('Create and verify RDFC proof with did:web and P-384', () async {
      // Generate a P-384 key pair
      final (keyPair, _) = P384KeyPair.generate();

      // Setup did:web identity
      final did = 'did:web:example.org';
      final vmId = '$did#key-1';

      // Create DID document
      final didDocument = DidDocument.fromJson({
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1'
        ],
        'id': did,
        'verificationMethod': [
          {
            'id': vmId,
            'type': 'JsonWebKey2020',
            'controller': did,
            'publicKeyJwk': _publicKeyToJwk(keyPair.publicKey),
          }
        ],
        'authentication': [vmId],
        'assertionMethod': [vmId]
      });

      // Create unsigned credential
      final unsignedVC = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Jane',
            'Lname': 'Smith',
          })
        ],
        issuanceDate: DateTime.parse('2020-01-01T00:00:00Z'),
        issuer: Issuer.uri(did),
      );

      // Sign the credential
      final signer = DidSigner(
        did: did,
        didKeyId: vmId,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_p384_sha384,
      );

      final generator = DataIntegrityEcdsaRdfcGenerator(
        signer: signer,
      );

      final issuedVC = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedVC),
        proofGenerator: generator,
      );

      // Verify the credential with custom DID resolver
      final didResolver = _TestDidResolver(didDocument);
      final verifier = DataIntegrityEcdsaRdfcVerifier(
          issuerDid: did, didResolver: didResolver);

      final result = await verifier.verify(issuedVC.toJson());

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });
  });
}

/// Simple DID resolver for testing
class _TestDidResolver implements DidResolver {
  final DidDocument _didDocument;

  _TestDidResolver(this._didDocument);

  @override
  Future<DidDocument> resolveDid(String did) async {
    if (did == _didDocument.id) {
      return _didDocument;
    }
    throw Exception('DID not found: $did');
  }
}

/// Converts a PublicKey to JWK format
Map<String, dynamic> _publicKeyToJwk(PublicKey publicKey) {
  // Use public_key_utils.keyToJwk which is not exported
  // So we manually create the JWK from the public key
  final bytes = publicKey.bytes;
  final keyType = publicKey.type;

  if (keyType == KeyType.p256) {
    // Decompress P-256 key
    return _ecPublicKeyToJwk(bytes, 'P-256', 32);
  } else if (keyType == KeyType.p384) {
    // Decompress P-384 key
    return _ecPublicKeyToJwk(bytes, 'P-384', 48);
  } else if (keyType == KeyType.p521) {
    // Decompress P-521 key
    return _ecPublicKeyToJwk(bytes, 'P-521', 66);
  } else {
    throw UnsupportedError('Key type $keyType not supported in test helper');
  }
}

/// Converts EC public key bytes to JWK
Map<String, dynamic> _ecPublicKeyToJwk(
    Uint8List compressedBytes, String crv, int coordinateLength) {
  // Use elliptic package curves
  final elliptic.Curve curve;
  if (crv == 'P-256') {
    curve = elliptic.getP256();
  } else if (crv == 'P-384') {
    curve = elliptic.getP384();
  } else if (crv == 'P-521') {
    curve = elliptic.getP521();
  } else {
    throw UnsupportedError('Curve $crv not supported in test helper');
  }

  final publicKey = curve.compressedHexToPublicKey(hex.encode(compressedBytes));

  // Extract x and y coordinates
  final xBytes = _bigIntToBytes(publicKey.X, coordinateLength);
  final yBytes = _bigIntToBytes(publicKey.Y, coordinateLength);

  // Base64url encode without padding
  final xBase64 = base64Encode(xBytes)
      .replaceAll('=', '')
      .replaceAll('+', '-')
      .replaceAll('/', '_');
  final yBase64 = base64Encode(yBytes)
      .replaceAll('=', '')
      .replaceAll('+', '-')
      .replaceAll('/', '_');

  return {
    'kty': 'EC',
    'crv': crv,
    'x': xBase64,
    'y': yBase64,
  };
}

/// Converts a BigInt to a fixed-length byte array
Uint8List _bigIntToBytes(BigInt value, int length) {
  final bytes = Uint8List(length);
  var v = value;
  for (var i = length - 1; i >= 0; i--) {
    bytes[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return bytes;
}
