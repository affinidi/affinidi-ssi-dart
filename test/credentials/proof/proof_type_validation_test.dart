import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

/// Test suite for validating proof type field requirements
/// According to VC Data Integrity v1.0 specification
void main() {
  group('Proof Type Validation - VC Data Integrity v1.0', () {
    late DidSigner signer;

    setUpAll(() async {
      signer = await initP256Signer(
        hexDecode(
          'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
        ),
      );
    });

    group('Empty Proof Type Validation', () {
      test('Should fail verification when proof type is null', () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-empty-type',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            // 'type' is intentionally missing
            'cryptosuite': 'ecdsa-rdfc-2019',
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z3invalidproofvalue',
          }
        };

        expect(
          () => LdVcDm1Suite().parse(jsonEncode(credential)),
          throwsA(isA<TypeError>()),
        );
      });

      test('Should fail verification when proof type is empty string',
          () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-empty-type',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': '', // Empty string
            'cryptosuite': 'ecdsa-rdfc-2019',
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z3invalidproofvalue',
          }
        };

        final vc = LdVcDm1Suite().parse(jsonEncode(credential));
        final isValid = await LdVcDm1Suite().verifyIntegrity(vc);

        expect(isValid, false);
      });

      test('Should fail verification when proof object is missing', () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-no-proof',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          // proof is missing entirely
        };

        final vc = LdVcDm1Suite().parse(jsonEncode(credential));
        final isValid = await LdVcDm1Suite().verifyIntegrity(vc);

        expect(isValid, false);
      });

      test('Should fail verification when proof is not a map', () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-invalid-proof',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': 'invalid_proof_string', // proof is not a map
        };

        expect(
          () => LdVcDm1Suite().parse(jsonEncode(credential)),
          throwsA(isA<TypeError>()),
        );
      });
    });

    group('Unsupported Proof Type Validation', () {
      test('Should fail verification for unsupported proof type', () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-unsupported-type',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'UnknownSignature2025', // Unsupported type
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z3invalidproofvalue',
          }
        };

        final vc = LdVcDm1Suite().parse(jsonEncode(credential));
        final isValid = await LdVcDm1Suite().verifyIntegrity(vc);

        expect(isValid, false);
      });

      test('Should fail verification for Ed25519Signature2020 (not supported)',
          () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
          ],
          'id': 'uuid:test-ed25519-2020',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'Ed25519Signature2020', // Not supported
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'invalid_jws',
          }
        };

        final vc = LdVcDm1Suite().parse(jsonEncode(credential));
        final isValid = await LdVcDm1Suite().verifyIntegrity(vc);

        expect(isValid, false);
      });
    });

    group('Supported Proof Types', () {
      test('Should accept DataIntegrityProof with ecdsa-rdfc-2019', () async {
        final unsignedCredential = MutableVcDataModelV1(
          context: MutableJsonLdContext.fromJson([
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ]),
          id: Uri.parse('uuid:test-supported-di-ecdsa'),
          type: {'VerifiableCredential'},
          credentialSubject: [
            MutableCredentialSubject({'id': 'did:example:123'})
          ],
          issuanceDate: DateTime.now(),
          issuer: Issuer.uri(signer.did),
        );

        final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
          signer: signer,
        );

        final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator,
        );

        expect(issuedCredential, isNotNull);
        final proof =
            issuedCredential.toJson()['proof'] as Map<String, dynamic>;
        expect(proof['type'], 'DataIntegrityProof');
        expect(proof['cryptosuite'], 'ecdsa-rdfc-2019');
      });

      test('Should accept EcdsaSecp256k1Signature2019', () async {
        final secp256k1Signer = await initSigner(
          hexDecode(
            'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
          ),
        );

        final unsignedCredential = MutableVcDataModelV1(
          context: MutableJsonLdContext.fromJson([
            'https://www.w3.org/2018/credentials/v1',
          ]),
          id: Uri.parse('uuid:test-supported-secp256k1'),
          type: {'VerifiableCredential'},
          credentialSubject: [
            MutableCredentialSubject({'id': 'did:example:123'})
          ],
          issuanceDate: DateTime.now(),
          issuer: Issuer.uri(secp256k1Signer.did),
        );

        final proofGenerator = Secp256k1Signature2019Generator(
          signer: secp256k1Signer,
        );

        final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator,
        );

        expect(issuedCredential, isNotNull);
        final proof =
            issuedCredential.toJson()['proof'] as Map<String, dynamic>;
        expect(proof['type'], 'EcdsaSecp256k1Signature2019');
      });
    });

    group('DataIntegrityProof - Unsupported Cryptosuite', () {
      test('Should fail verification for unsupported cryptosuite', () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-unsupported-cryptosuite',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'unknown-suite-2025', // Unsupported cryptosuite
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z3invalidproofvalue',
          }
        };

        final vc = LdVcDm1Suite().parse(jsonEncode(credential));
        final isValid = await LdVcDm1Suite().verifyIntegrity(vc);

        expect(isValid, false);
      });

      test(
          'Should fail verification when cryptosuite is null for DataIntegrityProof',
          () async {
        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-null-cryptosuite',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'DataIntegrityProof',
            // cryptosuite is missing
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z3invalidproofvalue',
          }
        };

        final vc = LdVcDm1Suite().parse(jsonEncode(credential));
        final isValid = await LdVcDm1Suite().verifyIntegrity(vc);

        expect(isValid, false);
      });
    });

    group('Verification - Proof Type Validation', () {
      test(
          'Should fail verification when proof type does not match expected type',
          () async {
        final unsignedCredential = MutableVcDataModelV1(
          context: MutableJsonLdContext.fromJson([
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ]),
          id: Uri.parse('uuid:test-verify-wrong-type'),
          type: {'VerifiableCredential'},
          credentialSubject: [
            MutableCredentialSubject({'id': 'did:example:123'})
          ],
          issuanceDate: DateTime.now(),
          issuer: Issuer.uri(signer.did),
        );

        final proofGenerator = DataIntegrityEcdsaRdfcGenerator(
          signer: signer,
        );

        final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator,
        );

        // Create a verifier with wrong expected proof type
        final proofVerifier = DataIntegrityEddsaRdfcVerifier(
          issuerDid: signer.did,
        );

        final result = await proofVerifier.verify(issuedCredential.toJson());

        expect(result.isValid, false);
        expect(
          result.errors,
          anyOf(
            contains(contains('invalid proof type')),
            contains(contains('invalid cryptosuite')),
          ),
        );
      });
    });

    group('Base Verifier - Empty Type Validation', () {
      test('DataIntegrity verifier should reject empty proof type', () async {
        final credentialWithEmptyType = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2',
          ],
          'id': 'uuid:test-base-verifier',
          'type': ['VerifiableCredential'],
          'issuer': signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': '', // Empty type
            'cryptosuite': 'ecdsa-rdfc-2019',
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z3invalidproofvalue',
          }
        };

        final verifier = DataIntegrityEcdsaRdfcVerifier(
          issuerDid: signer.did,
        );

        final result = await verifier.verify(credentialWithEmptyType);

        expect(result.isValid, false);
        expect(
          result.errors,
          contains(contains('proof type is required and cannot be empty')),
        );
      });

      test('Secp256k1 verifier should reject empty proof type', () async {
        final secp256k1Signer = await initSigner(
          hexDecode(
            'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
          ),
        );

        final credentialWithEmptyType = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
          ],
          'id': 'uuid:test-secp256k1-verifier',
          'type': ['VerifiableCredential'],
          'issuer': secp256k1Signer.did,
          'issuanceDate': DateTime.now().toIso8601String(),
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': '', // Empty type
            'created': DateTime.now().toIso8601String(),
            'verificationMethod': '${secp256k1Signer.did}#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'invalid_jws',
          }
        };

        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: secp256k1Signer.did,
        );

        final result = await verifier.verify(credentialWithEmptyType);

        expect(result.isValid, false);
        expect(
          result.errors,
          contains(contains('proof type is required and cannot be empty')),
        );
      });
    });
  });
}
