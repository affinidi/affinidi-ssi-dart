import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('SD-JWT Credential Validation Tests', () {
    final testSeed = Uint8List.fromList(
        utf8.encode('test seed for deterministic key generation'));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    test('Valid credential passes validation', () async {
      // Arrange
      final validCredential = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd',
        issuer: 'did:example:issuer',
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        credentialSubject: {
          'id': 'did:example:subject',
          'degree': {
            'type': 'BachelorDegree',
            'name': 'Bachelor of Science and Arts',
          },
        },
      );

      // Act & Assert - Should not throw
      final issuedCredential = await suite.issue(validCredential, signer);
      expect(issuedCredential, isNotNull);
    });

    test('Throws when context is empty', () async {
      // Arrange
      final credentialWithEmptyContext = MutableVcDataModelV2(
        context: [], // Empty context
        id: 'urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd',
        issuer: 'did:example:issuer',
        type: ['VerifiableCredential'],
        credentialSubject: {
          'id': 'did:example:subject',
          'name': 'Rain Bow',
        },
      );

      // Act & Assert
      expect(
        () => suite.issue(credentialWithEmptyContext, signer),
        throwsA(
          predicate<SsiException>(
            (e) => e.message.contains('Context is required'),
          ),
        ),
      );
    });

    test('Throws when context not include required URL', () async {
      // Arrange
      final credentialWithWrongContext = MutableVcDataModelV2(
        context: [
          'https://www.w3.org/2018/credentials/v1'
        ], // Wrong context URL
        id: 'urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd',
        issuer: 'did:example:issuer',
        type: ['VerifiableCredential'],
        credentialSubject: {
          'id': 'did:example:subject',
          'name': 'Rain Bow',
        },
      );

      // Act & Assert
      expect(
        () => suite.issue(credentialWithWrongContext, signer),
        throwsA(
          predicate<SsiException>(
            (e) => e.message.contains('Context must include'),
          ),
        ),
      );
    });

    test('Throws when type is empty', () async {
      // Arrange
      final credentialWithEmptyType = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd',
        issuer: 'did:example:issuer',
        type: [], // Empty type
        credentialSubject: {
          'id': 'did:example:subject',
          'name': 'Rain Bow',
        },
      );

      // Act & Assert
      expect(
        () => suite.issue(credentialWithEmptyType, signer),
        throwsA(
          predicate<SsiException>(
            (e) => e.message.contains('Type is required'),
          ),
        ),
      );
    });

    test('Throws when issuer is empty', () async {
      // Arrange
      final credentialWithEmptyIssuer = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd',
        issuer: '', // Empty issuer
        type: ['VerifiableCredential'],
        credentialSubject: {
          'id': 'did:example:subject',
          'name': 'Rain Bow',
        },
      );

      // Act & Assert
      expect(
        () => suite.issue(credentialWithEmptyIssuer, signer),
        throwsA(
          predicate<SsiException>(
            (e) => e.message.contains('Issuer is required'),
          ),
        ),
      );
    });

    test('Throws when credentialSubject is empty', () async {
      // Arrange
      final credentialWithEmptySubject = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd',
        issuer: 'did:example:issuer',
        type: ['VerifiableCredential'],
        credentialSubject: {}, // Empty credential subject
      );

      // Act & Assert
      expect(
        () => suite.issue(credentialWithEmptySubject, signer),
        throwsA(
          predicate<SsiException>(
            (e) => e.message.contains('Credential subject is required'),
          ),
        ),
      );
    });

    test('Reports multiple validation errors at once', () async {
      // Arrange
      final credentialWithMultipleErrors = MutableVcDataModelV2(
        context: [], // Empty context
        issuer: '', // Empty issuer
        type: [], // Empty type
        credentialSubject: {}, // Empty credential subject
      );

      // Act & Assert
      expect(
        () => suite.issue(credentialWithMultipleErrors, signer),
        throwsA(
          predicate<SsiException>(
            (e) =>
                e.message.contains('Context is required') &&
                e.message.contains('Type is required') &&
                e.message.contains('Issuer is required') &&
                e.message.contains('Credential subject is required'),
          ),
        ),
      );
    });
  });
}

Future<DidSigner> initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final keyPair = await wallet.createKeyPair("0-0");
  final doc = await DidKey.create(keyPair);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: keyPair,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
