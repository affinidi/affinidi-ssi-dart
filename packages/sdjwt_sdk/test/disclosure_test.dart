import 'dart:convert';

import 'package:sdjwt_sdk/src/base/hasher.dart';
import 'package:sdjwt_sdk/src/models/disclosure.dart';
import 'package:test/test.dart';

void main() {
  group('Disclosure', () {
    test('Create Disclosure', () {
      final disclosure = Disclosure.from(
        salt: 'salt123',
        claimName: 'age',
        claimValue: 30,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      expect(disclosure.salt, equals('salt123'));
      expect(disclosure.claimName, equals('age'));
      expect(disclosure.claimValue, equals(30));
    });

    test('Encode Disclosure', () {
      final disclosure = Disclosure.from(
        salt: 'salt123',
        claimName: 'age',
        claimValue: 30,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final encoded = disclosure.serialized;
      expect(encoded, isA<String>());
      expect(encoded, isNotEmpty);
    });

    test('Disclosure Digest', () {
      final disclosure = Disclosure.from(
        salt: 'salt123',
        claimName: 'age',
        claimValue: 30,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final digest = disclosure.digest;
      expect(digest, isA<String>());
      expect(digest, hasLength(43)); // Base64Url encoded SHA-256 hash length
    });

    test('Parse valid Disclosure', () {
      final original = Disclosure.from(
        salt: 'salt123',
        claimName: 'age',
        claimValue: 30,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final encoded = original.serialized;
      final parsed =
          Disclosure.parse(encoded, Base64EncodedOutputHasher.base64Sha256);

      expect(parsed.salt, equals(original.salt));
      expect(parsed.claimName, equals(original.claimName));
      expect(parsed.claimValue, equals(original.claimValue));
    });

    test('Parse invalid Disclosure - wrong format', () {
      final invalidEncoded = 'invalidEncodedString';
      expect(
          () => Disclosure.parse(
              invalidEncoded, Base64EncodedOutputHasher.base64Sha256),
          throwsFormatException);
    });

    test('Parse invalid Disclosure - wrong array length', () {
      final invalidJson = base64UrlEncode('["salt"]'.codeUnits);
      expect(
          () => Disclosure.parse(
              invalidJson, Base64EncodedOutputHasher.base64Sha256),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            'Invalid disclosure format',
          )));
    });

    test('Disclosure with different data types', () {
      final disclosureString = Disclosure.from(
        salt: 'salt1',
        claimName: 'name',
        claimValue: 'Rain Bow',
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final disclosureInt = Disclosure.from(
        salt: 'salt2',
        claimName: 'age',
        claimValue: 42,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final disclosureDouble = Disclosure.from(
        salt: 'salt3',
        claimName: 'height',
        claimValue: 1.75,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final disclosureBoolean = Disclosure.from(
        salt: 'salt4',
        claimName: 'isStudent',
        claimValue: true,
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final disclosureList = Disclosure.from(
        salt: 'salt5',
        claimName: 'hobbies',
        claimValue: ['reading', 'swimming'],
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );
      final disclosureMap = Disclosure.from(
        salt: 'salt6',
        claimName: 'address',
        claimValue: {'city': 'Amsterdam', 'country': 'Netherlands'},
        hasher: Base64EncodedOutputHasher.base64Sha256,
      );

      expect(disclosureString.claimValue, isA<String>());
      expect(disclosureInt.claimValue, isA<int>());
      expect(disclosureDouble.claimValue, isA<double>());
      expect(disclosureBoolean.claimValue, isA<bool>());
      expect(disclosureList.claimValue, isA<List>());
      expect(disclosureMap.claimValue, isA<Map>());

      for (final disclosure in [
        disclosureString,
        disclosureInt,
        disclosureDouble,
        disclosureBoolean,
        disclosureList,
        disclosureMap
      ]) {
        final encoded = disclosure.serialized;
        final parsed =
            Disclosure.parse(encoded, Base64EncodedOutputHasher.base64Sha256);
        expect(parsed.claimValue, equals(disclosure.claimValue));
      }
    });
  });
}
