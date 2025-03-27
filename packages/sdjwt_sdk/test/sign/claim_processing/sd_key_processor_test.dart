import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/sign/claim_processing/sd_key_processor.dart';
import 'package:test/test.dart';

void main() {
  late SdKeyProcessor processor;
  late List<String> localSdHashes;
  late Set<Disclosure> disclosures;

  setUp(() {
    processor = SdKeyProcessor();
    localSdHashes = [];
    disclosures = {};
  });

  group('SdKeyProcessor - Array Disclosures', () {
    test('should process array disclosures correctly', () {
      final List<dynamic> currentObject = ['value1', 'value2', 'value3'];
      final frameValue = [0, 2];

      processor.execute(SdKeyProcessorInput(
        currentObject,
        frameValue,
        localSdHashes,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
        'array',
      ));

      expect(currentObject[0], isA<Map<String, dynamic>>());
      expect((currentObject[0] as Map<String, dynamic>)['...'], isNotNull);
      expect(currentObject[1], equals('value2'));
      expect(currentObject[2], isA<Map<String, dynamic>>());
      expect((currentObject[2] as Map<String, dynamic>)['...'], isNotNull);
      expect(localSdHashes.length, equals(2));
      expect(disclosures.length, equals(2));
    });

    test('should throw error for invalid array index', () {
      final List<dynamic> currentObject = ['value1', 'value2'];
      final frameValue = [3];

      expect(
        () => processor.execute(SdKeyProcessorInput(
          currentObject,
          frameValue,
          localSdHashes,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
          'array',
        )),
        throwsArgumentError,
      );
    });

    test('should throw error for negative array index', () {
      final List<dynamic> currentObject = ['value1', 'value2'];
      final frameValue = [-1];

      expect(
        () => processor.execute(SdKeyProcessorInput(
          currentObject,
          frameValue,
          localSdHashes,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
          'array',
        )),
        throwsArgumentError,
      );
    });
  });

  group('SdKeyProcessor - Object Disclosures', () {
    test('should process object disclosures correctly', () {
      final Map<String, dynamic> currentObject = {
        'name': 'Rain',
        'age': 30,
        'email': 'Rain@example.com'
      };
      final frameValue = ['name', 'email'];

      processor.execute(SdKeyProcessorInput(
        currentObject,
        frameValue,
        localSdHashes,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
        'object',
      ));

      expect(currentObject.containsKey('name'), isFalse);
      expect(currentObject.containsKey('email'), isFalse);
      expect(currentObject['age'], equals(30));
      expect(localSdHashes.length, equals(2));
      expect(disclosures.length, equals(2));

      final disclosuresList = disclosures.toList();
      expect(
        disclosuresList.any((d) => d.claimName == 'name'),
        isTrue,
        reason: 'Should contain disclosure for "name"',
      );
      expect(
        disclosuresList.any((d) => d.claimName == 'email'),
        isTrue,
        reason: 'Should contain disclosure for "email"',
      );
    });

    test('should throw error for non-existent object key', () {
      final Map<String, dynamic> currentObject = {'name': 'Rain'};
      final frameValue = ['nonexistent'];

      expect(
        () => processor.execute(SdKeyProcessorInput(
          currentObject,
          frameValue,
          localSdHashes,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
          'object',
        )),
        throwsArgumentError,
      );
    });

    test('should throw error for null object value', () {
      final Map<String, dynamic> currentObject = {'name': null};
      final frameValue = ['name'];

      expect(
        () => processor.execute(SdKeyProcessorInput(
          currentObject,
          frameValue,
          localSdHashes,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
          'object',
        )),
        throwsArgumentError,
      );
    });
  });

  group('SdKeyProcessor - Invalid Input', () {
    test('should throw error for unsupported structure', () {
      final currentObject = 123;
      final frameValue = ['key'];

      expect(
        () => processor.execute(SdKeyProcessorInput(
          currentObject,
          frameValue,
          localSdHashes,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
          'invalid',
        )),
        throwsArgumentError,
      );
    });

    test('should handle empty frame value list', () {
      final Map<String, dynamic> currentObject = {'name': 'Rain'};
      final frameValue = <dynamic>[];

      processor.execute(SdKeyProcessorInput(
        currentObject,
        frameValue,
        localSdHashes,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
        'empty',
      ));

      expect(localSdHashes, isEmpty);
      expect(disclosures, isEmpty);
      expect(currentObject['name'], equals('Rain'));
    });
  });

  group('SdKeyProcessor - Hashing Algorithm', () {
    test('should use correct hashing algorithm for disclosures', () {
      final Map<String, dynamic> currentObject = {'name': 'Rain'};
      final frameValue = ['name'];

      processor.execute(SdKeyProcessorInput(
        currentObject,
        frameValue,
        localSdHashes,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
        'sha256',
      ));

      final sha256Disclosure = disclosures.first;
      disclosures.clear();
      localSdHashes.clear();

      currentObject['name'] = 'Rain';
      processor.execute(SdKeyProcessorInput(
        currentObject,
        frameValue,
        localSdHashes,
        disclosures,
        Base64EncodedOutputHasher.base64Sha512,
        'sha512',
      ));

      final sha512Disclosure = disclosures.first;

      expect(
        sha256Disclosure.digest.length,
        lessThan(sha512Disclosure.digest.length),
        reason: 'SHA-512 hash should be longer than SHA-256 hash',
      );
    });
  });
}
