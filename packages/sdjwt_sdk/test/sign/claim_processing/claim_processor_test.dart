import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/sign/claim_processing/claim_processor.dart';
import 'package:sdjwt_sdk/src/utils/common.dart';
import 'package:test/test.dart';

void main() {
  group('ClaimProcessor', () {
    late ClaimProcessor processor;

    setUp(() {
      processor = ClaimProcessor();
    });

    test('test dart dynamic behaviour', () {
      final claims = {
        'first_name': 'Rain',
        'last_name': 'Bow',
        'items': ['item1']
      };

      final sd = ['first_name'];
      claims['_sd'] = sd;
    });

    test('processes flat structure with single selective disclosure', () {
      final claims = {
        'first_name': 'Rain',
        'last_name': 'Bow',
      }.clone();

      final disclosureFrame = {
        '_sd': ['first_name']
      };

      final disclosures = <Disclosure>{};

      processor.execute(ClaimProcessorInput(
        claims,
        disclosureFrame,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
      ));

      expect(claims.containsKey('first_name'), isFalse);
      expect(claims['last_name'], equals('Bow'));
      expect(disclosures.length, equals(1));
    });

    test('processes nested object structure', () {
      final claims = {
        'user': {
          'name': 'Rain',
          'age': 30,
          'address': {'city': 'New York', 'country': 'USA'}
        }
      }.clone();

      final disclosureFrame = {
        'user': {
          '_sd': ['name'],
          'address': {
            '_sd': ['city']
          }
        }
      };

      final disclosures = <Disclosure>{};

      processor.execute(ClaimProcessorInput(
        claims,
        disclosureFrame,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
      ));

      expect(claims['user'], isA<Map>());
      expect((claims['user'] as Map).containsKey('name'), isFalse);
      expect((claims['user'] as Map)['age'], equals(30));
      expect(((claims['user'] as Map)['address'] as Map)['country'],
          equals('USA'));
      expect(disclosures.length, equals(2));
    });

    test('processes array structure', () {
      final claims = {
        'first_name': 'Rain',
        'items': [
          {'id': 1, 'name': 'Item 1'},
          {'id': 2, 'name': 'Item 2'}
        ]
      };

      final disclosureFrame = {
        '_sd': ['items']
      };

      final disclosures = <Disclosure>{};

      processor.execute(ClaimProcessorInput(
        claims,
        disclosureFrame,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
      ));

      expect(claims.containsKey('items'), isFalse);
      expect(disclosures.length, equals(1));
    });

    test('processes mixed types in array', () {
      final claims = {
        'mixed': [
          {'type': 'object'},
          'string',
          42,
          true
        ]
      };

      final disclosureFrame = {
        '_sd': ['mixed']
      };

      final disclosures = <Disclosure>{};

      processor.execute(ClaimProcessorInput(
        claims,
        disclosureFrame,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
      ));

      expect(claims.containsKey('mixed'), isFalse);
      expect(disclosures.length, equals(1));
    });

    test('processes nested arrays', () {
      final claims = {
        'first_name': 'Rain',
        'matrix': [
          [1, 2, 3],
          [4, 5, 6]
        ]
      };

      final disclosureFrame = {
        '_sd': ['matrix']
      };

      final disclosures = <Disclosure>{};

      processor.execute(ClaimProcessorInput(
        claims,
        disclosureFrame,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
      ));

      expect(claims.containsKey('matrix'), isFalse);
      expect(disclosures.length, equals(1));
    });

    test('handles multiple selective disclosures at different levels', () {
      final claims = {
        'id': '234234',
        'village': 'Hilversum',
        'user': {
          'name': 'Rain',
          'contacts': [
            {'email': 'Rain@example.com'},
            {'email': 'Rain.Bow@example.com'}
          ]
        }
      }.clone();

      final disclosureFrame = {
        '_sd': ['village'],
        'user': {
          '_sd': ['name'],
          'contacts': {
            '0': {
              '_sd': ['email']
            }
          }
        }
      };

      final disclosures = <Disclosure>{};

      processor.execute(ClaimProcessorInput(
        claims,
        disclosureFrame,
        disclosures,
        Base64EncodedOutputHasher.base64Sha256,
      ));

      expect((claims['user'] as Map).containsKey('name'), isFalse);
      expect(((claims['user'] as Map)['contacts'] as List).length, equals(2));
      expect(disclosures.length, equals(3));
    });

    test('throws ArgumentError for invalid _sd structure', () {
      final claims = {'name': 'Rain'};
      final disclosureFrame = {'_sd': 'invalid'};

      final disclosures = <Disclosure>{};

      expect(
        () => processor.execute(ClaimProcessorInput(
          claims,
          disclosureFrame,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
        )),
        throwsArgumentError,
      );
    });

    test('throws ArgumentError for non-existent disclosure key', () {
      final claims = {'name': 'Rain'};
      final disclosureFrame = {
        '_sd': ['non_existent_key']
      };

      final disclosures = <Disclosure>{};

      expect(
        () => processor.execute(ClaimProcessorInput(
          claims,
          disclosureFrame,
          disclosures,
          Base64EncodedOutputHasher.base64Sha256,
        )),
        throwsArgumentError,
      );
    });
  });
}
