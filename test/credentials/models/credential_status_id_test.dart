import 'package:test/test.dart';
import 'package:ssi/ssi.dart';

/// Tests to verify that credentialStatus.id field follows VCDM specifications:
/// - VCDM v1.1: id is REQUIRED
/// - VCDM v2.0: id is OPTIONAL
void main() {
  group('CredentialStatus id field validation', () {
    group('VCDM v1.1 (CredentialStatusV1)', () {
      test('should require id field (immutable)', () {
        expect(
          () => CredentialStatusV1.fromJson({
            'type': 'RevocationList2020Status',
            // Missing 'id' field - should throw
          }),
          throwsA(isA<SsiException>()),
          reason: 'VCDM v1.1 spec requires id field in credentialStatus',
        );
      });

      test('should accept id field (immutable)', () {
        final status = CredentialStatusV1.fromJson({
          'id': 'https://example.com/status/1',
          'type': 'RevocationList2020Status',
        });

        expect(status.id.toString(), 'https://example.com/status/1');
        expect(status.type, 'RevocationList2020Status');
      });

      test('should allow null id in mutable version', () {
        final status = MutableCredentialStatusV1({
          'type': 'RevocationList2020Status',
          // Missing 'id' field
        });

        expect(status.id, isNull);
        expect(status.type, 'RevocationList2020Status');
      });
    });

    group('VCDM v2.0 (CredentialStatusV2)', () {
      test('should allow missing id field (immutable)', () {
        final status = CredentialStatusV2.fromJson({
          'type': 'RevocationList2020Status',
          // Missing 'id' field - should NOT throw
        });

        expect(status.id, isNull);
        expect(status.type, 'RevocationList2020Status');
      });

      test('should accept id field when present (immutable)', () {
        final status = CredentialStatusV2.fromJson({
          'id': 'https://example.com/status/2',
          'type': 'RevocationList2020Status',
        });

        expect(status.id.toString(), 'https://example.com/status/2');
        expect(status.type, 'RevocationList2020Status');
      });

      test('should allow missing id in mutable version', () {
        final status = MutableCredentialStatusV2({
          'type': 'RevocationList2020Status',
          // Missing 'id' field
        });

        expect(status.id, isNull);
        expect(status.type, 'RevocationList2020Status');
      });
    });

    group('Serialization consistency', () {
      test('V1 should include id in JSON output', () {
        final status = CredentialStatusV1.fromJson({
          'id': 'https://example.com/status/1',
          'type': 'RevocationList2020Status',
        });

        final json = status.toJson();
        expect(json['id'], 'https://example.com/status/1');
        expect(json['type'], 'RevocationList2020Status');
      });

      test('V2 should omit null id in JSON output', () {
        final status = CredentialStatusV2.fromJson({
          'type': 'RevocationList2020Status',
        });

        final json = status.toJson();
        expect(json.containsKey('id'), isFalse);
        expect(json['type'], 'RevocationList2020Status');
      });

      test('V2 should include id in JSON output when present', () {
        final status = CredentialStatusV2.fromJson({
          'id': 'https://example.com/status/2',
          'type': 'RevocationList2020Status',
        });

        final json = status.toJson();
        expect(json['id'], 'https://example.com/status/2');
        expect(json['type'], 'RevocationList2020Status');
      });
    });
  });
}
