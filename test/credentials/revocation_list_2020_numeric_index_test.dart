import 'package:ssi/src/credentials/models/field_types/credential_status/revocation_list_2020.dart';
import 'package:test/test.dart';

void main() {
  group('RevocationList2020Status with Numeric revocationListIndex', () {
    test('should parse credentialStatus directly with Numeric revocationListIndex', () {
      final statusJsonWithNumber = {
        'id': 'https://example.com/status#7',
        'type': 'RevocationList2020Status',
        'revocationListIndex': 7, // This is a number, not a string
        'revocationListCredential': 'https://example.com/status'
      };

      expect(
        () => RevocationList2020Status.fromJson(statusJsonWithNumber),
        returnsNormally,
      );

      final status = RevocationList2020Status.fromJson(statusJsonWithNumber);

      expect(status.revocationListIndex, equals('7'));
      expect(status.type, equals('RevocationList2020Status'));
      expect(status.revocationListCredential, equals('https://example.com/status'));
    });

    test('should parse credentialStatus directly with String revocationListIndex', () {
      final statusJsonWithString = {
        'id': 'https://example.com/status#7',
        'type': 'RevocationList2020Status',
        'revocationListIndex': '7', // This is a string
        'revocationListCredential': 'https://example.com/status'
      };

      expect(
        () => RevocationList2020Status.fromJson(statusJsonWithString),
        returnsNormally,
      );

      final status = RevocationList2020Status.fromJson(statusJsonWithString);
      expect(status.revocationListIndex, equals('7'));
      expect(status.type, equals('RevocationList2020Status'));
    });

    test('RevocationList2020Status.fromJson should handle numeric index', () {
      final statusJsonWithNumber = {
        'id': 'https://example.com/status#7',
        'type': 'RevocationList2020Status',
        'revocationListIndex': 7,
        'revocationListCredential': 'https://example.com/status'
      };

      expect(
        () => RevocationList2020Status.fromJson(statusJsonWithNumber),
        returnsNormally,
      );

      final status = RevocationList2020Status.fromJson(statusJsonWithNumber);
      expect(status.revocationListIndex, equals('7'));
    });

    test('RevocationList2020Status.fromJson should handle string index', () {
      final statusJsonWithString = {
        'id': 'https://example.com/status#7',
        'type': 'RevocationList2020Status',
        'revocationListIndex': '7',
        'revocationListCredential': 'https://example.com/status'
      };

      final status = RevocationList2020Status.fromJson(statusJsonWithString);
      expect(status.revocationListIndex, equals('7'));
    });

    test('MutableRevocationList2020Status should handle numeric index', () {
      final statusJsonWithNumber = {
        'id': 'https://example.com/status#7',
        'type': 'RevocationList2020Status',
        'revocationListIndex': 7,
        'revocationListCredential': 'https://example.com/status'
      };

      final status =
          MutableRevocationList2020Status.fromJson(statusJsonWithNumber);
      expect(status.revocationListIndex, equals('7'));
    });

    test('should handle zero as numeric index', () {
      final statusJson = {
        'id': 'https://example.com/status#0',
        'type': 'RevocationList2020Status',
        'revocationListIndex': 0,
        'revocationListCredential': 'https://example.com/status'
      };

      final status = RevocationList2020Status.fromJson(statusJson);
      expect(status.revocationListIndex, equals('0'));
    });

    test('should handle large numeric index', () {
      final statusJson = {
        'id': 'https://example.com/status#999999',
        'type': 'RevocationList2020Status',
        'revocationListIndex': 999999,
        'revocationListCredential': 'https://example.com/status'
      };

      final status = RevocationList2020Status.fromJson(statusJson);
      expect(status.revocationListIndex, equals('999999'));
    });

    test('should handle double as index', () {
      final statusJson = {
        'id': 'https://example.com/status#42',
        'type': 'RevocationList2020Status',
        'revocationListIndex': 42.0,
        'revocationListCredential': 'https://example.com/status'
      };

      final status = RevocationList2020Status.fromJson(statusJson);
      expect(status.revocationListIndex, equals('42.0'));
    });
  });
}

