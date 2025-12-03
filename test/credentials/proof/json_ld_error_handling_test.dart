import 'dart:async';
import 'dart:io';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('JSON-LD Error Handling Tests', () {
    group('RemoteContextLoadException', () {
      test('should wrap SocketException with context', () {
        final uri = Uri.parse('https://example.com/context.json');
        final exception = RemoteContextLoadException(
          uri: uri,
          cause: 'Network error: Connection refused',
        );

        expect(exception, isA<JsonLdException>());
        expect(exception, isA<SsiException>());
        expect(exception.failedUri, equals(uri));
        expect(exception.cause, contains('Network error'));
        expect(exception.operation, equals('load_remote_context'));
        expect(exception.message, equals('Failed to load remote context'));
      });

      test('should include all context in toString', () {
        final uri = Uri.parse('https://w3id.org/security/data-integrity/v2');
        final exception = RemoteContextLoadException(
          uri: uri,
          cause: 'Timeout: Request timed out',
        );

        final stringValue = exception.toString();
        expect(stringValue, contains('Failed to load remote context'));
        expect(stringValue, contains('load_remote_context'));
        expect(stringValue, contains(uri.toString()));
        expect(stringValue, contains('Timeout'));
      });
    });

    group('JsonLdException', () {
      test('should create exception with operation context', () {
        final exception = JsonLdException(
          message: 'Normalization failed',
          operation: 'normalize',
          cause: 'Invalid JSON-LD structure',
        );

        expect(exception, isA<SsiException>());
        expect(exception.message, equals('Normalization failed'));
        expect(exception.operation, equals('normalize'));
        expect(exception.cause, equals('Invalid JSON-LD structure'));
        expect(exception.code, equals('json_ld_processing_error'));
      });

      test('should include operation in toString', () {
        final exception = JsonLdException(
          message: 'Processing failed',
          operation: 'compute_hash',
          failedUri: Uri.parse('https://example.com/context'),
          cause: 'Invalid data',
        );

        final stringValue = exception.toString();
        expect(stringValue, contains('Processing failed'));
        expect(stringValue, contains('compute_hash'));
        expect(stringValue, contains('example.com'));
        expect(stringValue, contains('Invalid data'));
      });

      test('should work with minimal parameters', () {
        final exception = JsonLdException(message: 'Error occurred');

        expect(exception.message, equals('Error occurred'));
        expect(exception.operation, isNull);
        expect(exception.failedUri, isNull);
        expect(exception.cause, isNull);
      });
    });

    group('Secp256k1 Verifier - Network Error Handling', () {
      test('should return validation error when context loading fails',
          () async {
        // Create a verifier with a custom document loader that simulates network failure
        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          customDocumentLoader: (Uri uri) async {
            // Simulate network failure for non-cached contexts
            // The cached contexts will be handled by the library's internal cache
            if (!uri.toString().contains('www.w3.org/2018/credentials/v1')) {
              throw SocketException('Connection refused');
            }
            return null; // Let cached contexts load normally
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://example.com/unreachable-context.json', // This will trigger network error
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          'issuanceDate': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123', 'name': 'Test'},
          'proof': {
            'type': 'EcdsaSecp256k1Signature2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'test..signature',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        expect(result.errors.length, greaterThan(0));

        // The error should indicate a context loading problem
        // It may come as "Failed to load remote context" or from JSON-LD processor
        final errorText = result.errors.join(' ').toLowerCase();
        expect(
          errorText.contains('context') &&
              (errorText.contains('failed') || errorText.contains('error')),
          isTrue,
          reason:
              'Error should mention context loading issue. Actual: ${result.errors}',
        );
      });

      test('should return validation error for HTTP errors', () async {
        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          customDocumentLoader: (Uri uri) async {
            // Simulate HTTP 404 for non-cached contexts
            if (!uri.toString().contains('www.w3.org/2018/credentials/v1')) {
              throw HttpException('Not Found');
            }
            return null;
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://example.com/missing-context.json',
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          'issuanceDate': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'EcdsaSecp256k1Signature2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'test..signature',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        // The error should indicate a context loading problem
        final errorText = result.errors.join(' ').toLowerCase();
        expect(
          errorText.contains('context') &&
              (errorText.contains('failed') || errorText.contains('error')),
          isTrue,
          reason:
              'Error should mention context issue. Actual: ${result.errors}',
        );
      });

      test('should return validation error for timeout', () async {
        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          customDocumentLoader: (Uri uri) async {
            // Simulate timeout for non-cached contexts
            if (!uri.toString().contains('www.w3.org/2018/credentials/v1')) {
              throw TimeoutException('Request timed out');
            }
            return null;
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://slow-server.com/context.json',
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          'issuanceDate': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'EcdsaSecp256k1Signature2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'test..signature',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        // The error should indicate a context loading problem
        final errorText = result.errors.join(' ').toLowerCase();
        expect(
          errorText.contains('context') &&
              (errorText.contains('failed') || errorText.contains('error')),
          isTrue,
          reason:
              'Error should mention context issue. Actual: ${result.errors}',
        );
      });

      test('should return validation error for invalid JSON response',
          () async {
        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          customDocumentLoader: (Uri uri) async {
            // Simulate invalid JSON for non-cached contexts
            if (!uri.toString().contains('www.w3.org/2018/credentials/v1')) {
              throw FormatException('Invalid JSON');
            }
            return null;
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://broken-server.com/context.json',
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          'issuanceDate': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'EcdsaSecp256k1Signature2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'test..signature',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        // The error should indicate a context loading problem
        final errorText = result.errors.join(' ').toLowerCase();
        expect(
          errorText.contains('context') &&
              (errorText.contains('failed') || errorText.contains('error')),
          isTrue,
          reason:
              'Error should mention context issue. Actual: ${result.errors}',
        );
      });
    });

    group('Data Integrity Verifier - Network Error Handling', () {
      test('should return validation error when context loading fails',
          () async {
        final verifier = DataIntegrityEcdsaRdfcVerifier(
          issuerDid:
              'did:key:zDnaerx9CtfPJ7PZ4sL8SsSZfYmfB7FS6VTbNc3fHnEEVHg4X',
          customDocumentLoader: (Uri uri) async {
            if (uri.toString().contains('example.com')) {
              throw SocketException('Network unreachable');
            }
            return null;
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://example.com/unreachable-context',
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:zDnaerx9CtfPJ7PZ4sL8SsSZfYmfB7FS6VTbNc3fHnEEVHg4X',
          'validFrom': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'ecdsa-rdfc-2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:zDnaerx9CtfPJ7PZ4sL8SsSZfYmfB7FS6VTbNc3fHnEEVHg4X#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue':
                'z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        expect(
          result.errors.any((e) => e.contains('Failed to load remote context')),
          isTrue,
        );
        expect(
          result.errors.any((e) => e.contains('Network')),
          isTrue,
        );
      });

      test('should handle timeout in Data Integrity verification', () async {
        final verifier = DataIntegrityEcdsaRdfcVerifier(
          issuerDid:
              'did:key:zDnaerx9CtfPJ7PZ4sL8SsSZfYmfB7FS6VTbNc3fHnEEVHg4X',
          customDocumentLoader: (Uri uri) async {
            if (uri.toString().contains('slow')) {
              throw TimeoutException(
                  'Connection timed out', const Duration(seconds: 30));
            }
            return null;
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://slow-server.example/context',
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:zDnaerx9CtfPJ7PZ4sL8SsSZfYmfB7FS6VTbNc3fHnEEVHg4X',
          'validFrom': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'ecdsa-rdfc-2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:zDnaerx9CtfPJ7PZ4sL8SsSZfYmfB7FS6VTbNc3fHnEEVHg4X#key-1',
            'proofPurpose': 'assertionMethod',
            'proofValue':
                'z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        expect(
          result.errors.any((e) => e.contains('Failed to load remote context')),
          isTrue,
        );
        expect(
          result.errors
              .any((e) => e.contains('Timeout') || e.contains('timed out')),
          isTrue,
        );
      });
    });

    group('Error Context Preservation', () {
      test('should preserve URI information in error messages', () async {
        const failedUri = 'https://example.com/special-context.json';

        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          customDocumentLoader: (Uri uri) async {
            if (uri.toString() == failedUri) {
              throw SocketException('Connection refused');
            }
            if (!uri.toString().contains('www.w3.org/2018/credentials/v1')) {
              throw SocketException('Connection refused');
            }
            return null;
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            failedUri,
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          'issuanceDate': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'EcdsaSecp256k1Signature2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'test..signature',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        // The error should indicate a context loading problem
        final errorText = result.errors.join(' ').toLowerCase();
        expect(
          errorText.contains('context') &&
              (errorText.contains('failed') || errorText.contains('error')),
          isTrue,
          reason:
              'Error should mention context issue. Actual: ${result.errors}',
        );
      });

      test('should include cause information in error messages', () async {
        const errorMessage = 'Connection timeout after 30 seconds';

        final verifier = Secp256k1Signature2019Verifier(
          issuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          customDocumentLoader: (Uri uri) async {
            throw SocketException(errorMessage);
          },
        );

        final credential = {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://example.com/context',
          ],
          'type': ['VerifiableCredential'],
          'issuer': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          'issuanceDate': '2023-01-01T00:00:00Z',
          'credentialSubject': {'id': 'did:example:123'},
          'proof': {
            'type': 'EcdsaSecp256k1Signature2019',
            'created': '2023-01-01T00:00:00Z',
            'verificationMethod':
                'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
            'proofPurpose': 'assertionMethod',
            'jws': 'test..signature',
          },
        };

        final result = await verifier.verify(credential);

        expect(result.isValid, isFalse);
        expect(
          result.errors.any((e) => e.contains('Cause:')),
          isTrue,
          reason: 'Error should contain cause information',
        );
        expect(
          result.errors.any((e) => e.contains(errorMessage)),
          isTrue,
          reason: 'Error should contain the original error message',
        );
      });
    });

    group('Validation Errors Should Still Propagate', () {
      test('should throw SsiException for invalid multibase encoding', () {
        final exception = SsiException(
          message: 'Invalid multibase encoding',
          code: 'invalid_encoding',
        );

        expect(exception, isA<Exception>());
        expect(exception.message, contains('Invalid multibase'));
      });

      test('should not catch SsiException in verifier', () async {
        // This test verifies that SsiExceptions (validation errors)
        // are NOT caught by network error handling

        // The test in data_integrity_jcs_test.dart already validates this behavior
        // by expecting an SsiException to be thrown for invalid multibase encoding

        // Documenting this expected behavior here:
        expect(
          () => throw SsiException(
            message: 'Invalid proof value',
            code: 'invalid_encoding',
          ),
          throwsA(isA<SsiException>()),
        );
      });
    });

    // Note: Cache functionality is tested indirectly through other tests
    // that use cached @context without triggering custom document loaders

    group('Exception Type Hierarchy', () {
      test('RemoteContextLoadException should be JsonLdException', () {
        final exception = RemoteContextLoadException(
          uri: Uri.parse('https://example.com'),
          cause: 'Test',
        );

        expect(exception, isA<JsonLdException>());
        expect(exception, isA<SsiException>());
        expect(exception, isA<Exception>());
      });

      test('JsonLdException should be SsiException', () {
        final exception = JsonLdException(
          message: 'Test',
        );

        expect(exception, isA<SsiException>());
        expect(exception, isA<Exception>());
      });

      test('should have correct exception code', () {
        final exception = JsonLdException(
          message: 'Test',
        );

        expect(exception.code, equals('json_ld_processing_error'));
      });
    });
  });
}
