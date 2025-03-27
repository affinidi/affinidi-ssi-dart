import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/sign/claim_processing/claim_processing_visitor.dart';
import 'package:sdjwt_sdk/src/sign/claim_processing/sd_key_processor.dart';
import 'package:sdjwt_sdk/src/utils/common.dart';
import 'package:sdjwt_sdk/src/utils/stack.dart';
import 'package:test/test.dart';

void main() {
  late ClaimProcessingVisitor visitor;
  late SdKeyProcessor sdKeyProcessor;
  late Set<Disclosure> disclosures;
  late Hasher<String, String> hasher;

  setUp(() {
    sdKeyProcessor = SdKeyProcessor();
    disclosures = {};
    hasher = Base64EncodedOutputHasher.base64Sha256;
    visitor = ClaimProcessingVisitor(disclosures, hasher, sdKeyProcessor);
  });

  void processElement(ClaimElement element, {String path = ''}) {
    final stack = Stack<ClaimElement>(source: [element]);
    while (stack.isNotEmpty) {
      final currentElement = stack.pop();
      currentElement.accept(visitor, path);
      stack.pushAll(visitor.stack);
      visitor.stack.clear();
    }
  }

  void verifyDisclosures(int expectedCount) {
    expect(disclosures.length, equals(expectedCount));
  }

  MapClaimElement createMapElement(Map<String, dynamic> value, dynamic frame) {
    return MapClaimElement(value, frame, []);
  }

  ListClaimElement createListElement(List<dynamic> value, dynamic frame) {
    return ListClaimElement(value, frame, []);
  }

  void verifyFieldDisclosed(Map<String, dynamic> map, String field,
      {bool shouldExist = false}) {
    expect(map.containsKey(field), equals(shouldExist));
    if (!shouldExist) {
      expect(map.containsKey('_sd'), isTrue);
    }
  }

  group('ClaimProcessingVisitor - Map Element Processing', () {
    test('should process map elements correctly', () {
      final Map<String, dynamic> value = {
        'name': 'Rain',
        'email': 'rain@example.com',
        'age': 30
      };
      final Map<String, dynamic> disclosureFrame = {
        '_sd': ['name', 'email']
      };

      final element = createMapElement(value, disclosureFrame);
      element.accept(visitor, '');

      verifyFieldDisclosed(value, 'name');
      verifyFieldDisclosed(value, 'email');
      verifyFieldDisclosed(value, 'age', shouldExist: true);
      expect(value['age'], equals(30));
      verifyDisclosures(2);
    });

    test('should handle nested map structures', () {
      final value = {
        'name': 'Rain',
        'address': {
          'street': 'Some street',
          'city': 'Anytown',
          'zipCode': '70707'
        }
      }.clone();
      final Map<String, dynamic> disclosureFrame = {
        'address': {
          '_sd': ['street', 'zipCode']
        }
      };

      final element = createMapElement(value, disclosureFrame);
      processElement(element);

      expect(value['name'], equals('Rain'));
      expect(value['address'], isA<Map>());

      final address = value['address'] as Map<String, dynamic>;
      verifyFieldDisclosed(address, 'street');
      verifyFieldDisclosed(address, 'zipCode');
      verifyFieldDisclosed(address, 'city', shouldExist: true);
      verifyDisclosures(2);
    });

    test('should throw error for invalid disclosure frame', () {
      final Map<String, dynamic> value = {'name': 'Rain'};
      final invalidFrame = "not a map";
      final element = createMapElement(value, invalidFrame);

      expect(
        () => element.accept(visitor, ''),
        throwsArgumentError,
      );
    });
  });

  group('ClaimProcessingVisitor - List Element Processing', () {
    test('should process list elements correctly', () {
      final List<dynamic> favMovies = ['Sholey', 'Titanic', 'IronMan'];
      final Map<String, dynamic> disclosureFrame = {
        '_sd': [0, 2]
      };

      final element = createListElement(favMovies, disclosureFrame);
      element.accept(visitor, '');

      expect(favMovies[0], isA<Map>());
      expect(favMovies[1], equals('Titanic'));
      expect(favMovies[2], isA<Map>());
      verifyDisclosures(2);
    });

    test('should handle nested lists', () {
      final value = {
        'name': 'Rain',
        'hobbies': ['reading', 'coding', 'surfing', 'hiking']
      }.clone();
      final Map<String, dynamic> disclosureFrame = {
        'hobbies': {
          '_sd': [1, 3]
        }
      };

      final element = createMapElement(value, disclosureFrame);
      processElement(element);

      expect(value['name'], equals('Rain'));
      expect(value['hobbies'], isA<List>());

      final hobbies = value['hobbies'] as List<dynamic>;
      expect(hobbies[0], equals('reading'));
      expect(hobbies[1], isA<Map>());
      expect(hobbies[2], equals('surfing'));
      expect(hobbies[3], isA<Map>());
      verifyDisclosures(2);
    });

    test('should throw error on invalid list indices in disclosure frame', () {
      final List<dynamic> value = ['item1', 'item2'];
      final Map<String, dynamic> disclosureFrame = {
        '_sd': [0],
        '5': 'invalid index'
      };

      final element = createListElement(value, disclosureFrame);
      expect(
        () => element.accept(visitor, ''),
        throwsArgumentError,
      );
    });
  });

  group('ClaimProcessingVisitor - SD Key Processing', () {
    test('should process _sd key correctly', () {
      final Map<String, dynamic> value = {
        'name': 'Rain',
        'email': 'rain@example.com'
      };
      final Map<String, dynamic> disclosureFrame = {
        '_sd': ['name']
      };

      final element = createMapElement(value, disclosureFrame);
      element.accept(visitor, '');

      verifyFieldDisclosed(value, 'name');
      verifyFieldDisclosed(value, 'email', shouldExist: true);
      verifyDisclosures(1);
    });

    test('should throw error for invalid _sd structure', () {
      final Map<String, dynamic> value = {'name': 'Rain'};
      final Map<String, dynamic> disclosureFrame = {'_sd': 'invalid'};
      final element = createMapElement(value, disclosureFrame);

      expect(
        () => element.accept(visitor, ''),
        throwsArgumentError,
      );
    });
  });

  group('ClaimProcessingVisitor - Path Construction', () {
    test('should construct correct paths', () {
      expect(constructFullPath('', 'name'), equals('name'));
      expect(constructFullPath('person', 'name'), equals('person.[name]'));
      expect(constructFullPath('person.[address]', 'street'),
          equals('person.[address].[street]'));
    });
  });

  group('ClaimProcessingVisitor - Complex Structures', () {
    test('should handle complex nested structures with multiple disclosures',
        () {
      final value = {
        'person': {
          'name': 'Rain',
          'contact': {'email': 'rain@example.com', 'phone': '111-2222'},
          'addresses': [
            {'type': 'home', 'street': 'Someweg', 'city': 'Amsterdam'},
            {'type': 'work', 'street': 'Workweg', 'city': 'Workplace'}
          ]
        }
      }.clone();

      final Map<String, dynamic> disclosureFrame = {
        'person': {
          'contact': {
            '_sd': ['email']
          },
          'addresses': {
            '0': {
              '_sd': ['street']
            },
            '1': {
              '_sd': ['street', 'city']
            }
          }
        }
      };

      final element = createMapElement(value, disclosureFrame);
      processElement(element);

      final person = value['person'] as Map<String, dynamic>;
      final contact = person['contact'] as Map<String, dynamic>;
      final addresses = person['addresses'] as List<dynamic>;
      final address0 = addresses[0] as Map<String, dynamic>;
      final address1 = addresses[1] as Map<String, dynamic>;

      verifyFieldDisclosed(contact, 'email');
      verifyFieldDisclosed(contact, 'phone', shouldExist: true);

      verifyFieldDisclosed(address0, 'street');
      verifyFieldDisclosed(address0, 'city', shouldExist: true);

      verifyFieldDisclosed(address1, 'street');
      verifyFieldDisclosed(address1, 'city');

      verifyDisclosures(4);
    });
  });
}
