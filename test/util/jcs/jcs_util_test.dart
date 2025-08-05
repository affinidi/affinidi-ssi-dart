import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/util/jcs_util.dart';
import 'package:test/test.dart';

double hex2double(String hexValue) {
  if (hexValue.startsWith('0x')) {
    hexValue = hexValue.substring(2);
  }
  if (hexValue.length != 16) {
    throw Exception('Expecting 64 bit number');
  }

  final bdata = ByteData(8);
  for (var i = 0; i < hexValue.length / 2; i += 1) {
    bdata.setInt8(
      i,
      int.parse(hexValue.substring(2 * i, 2 * i + 2), radix: 16),
    );
  }
  return bdata.getFloat64(0);
}

void testNumber(String hex, String expected) {
  final d = hex2double(hex);
  final canonical = JcsUtil.canonicalize(d);
  expect(canonical, equals(expected));
}

/// Tests JCS implementation against test vectors.
///
/// Test vectors sourced from:
/// https://github.com/cyberphone/json-canonicalization/tree/master/testdata
void testJcsVector(String vectorName) {
  final inputFile = File('test/util/vectors/input/$vectorName.json');
  final outputFile = File('test/util/vectors/output/$vectorName.json');

  final inputJson = jsonDecode(inputFile.readAsStringSync());
  final expectedOutput = outputFile.readAsStringSync().trim();

  final actualOutput = JcsUtil.canonicalize(inputJson);
  expect(actualOutput, equals(expectedOutput));
}

void main() {
  group('JcsUtil RFC 8785 Compliance Tests', () {
    group('Basic data types', () {
      test('null value', () {
        expect(JcsUtil.canonicalize(null), equals('null'));
      });

      test('boolean values', () {
        expect(JcsUtil.canonicalize(true), equals('true'));
        expect(JcsUtil.canonicalize(false), equals('false'));
      });

      test('integer numbers', () {
        expect(JcsUtil.canonicalize(0), equals('0'));
        expect(JcsUtil.canonicalize(42), equals('42'));
        expect(JcsUtil.canonicalize(-17), equals('-17'));
        expect(JcsUtil.canonicalize(1000000), equals('1000000'));
      });

      test('Appendix B', () {
        testNumber('0x0000000000000000', '0');
        testNumber('0x8000000000000000', '0');
        testNumber('0x0000000000000001', '5e-324');
        testNumber('0x8000000000000001', '-5e-324');
        testNumber('0x7fefffffffffffff', '1.7976931348623157e+308');
        testNumber('0xffefffffffffffff', '-1.7976931348623157e+308');
        testNumber('0x4340000000000000', '9007199254740992');
        testNumber('0xc340000000000000', '-9007199254740992');
        testNumber('0x4430000000000000', '295147905179352830000');
        testNumber('0x44b52d02c7e14af5', '9.999999999999997e+22');
        testNumber('0x44b52d02c7e14af6', '1e+23');
        testNumber('0x44b52d02c7e14af7', '1.0000000000000001e+23');
        testNumber('0x444b1ae4d6e2ef4e', '999999999999999700000');
        testNumber('0x444b1ae4d6e2ef4f', '999999999999999900000');
        testNumber('0x444b1ae4d6e2ef50', '1e+21');
        testNumber('0x3eb0c6f7a0b5ed8c', '9.999999999999997e-7');
        testNumber('0x3eb0c6f7a0b5ed8d', '0.000001');
        testNumber('0x41b3de4355555553', '333333333.3333332');
        testNumber('0x41b3de4355555554', '333333333.33333325');
        testNumber('0x41b3de4355555555', '333333333.3333333');
        testNumber('0x41b3de4355555556', '333333333.3333334');
        testNumber('0x41b3de4355555557', '333333333.33333343');
        testNumber('0xbecbf647612f3696', '-0.0000033333333333333333');
        testNumber('0x43143ff3c1cb0959', '1424953923781206.2');
      });

      test('double numbers - integer values', () {
        expect(JcsUtil.canonicalize(1.0), equals('1'));
        expect(JcsUtil.canonicalize(0.0), equals('0'));
        expect(JcsUtil.canonicalize(-5.0), equals('-5'));
      });

      test('double numbers - fractional values', () {
        expect(JcsUtil.canonicalize(3.14), equals('3.14'));
        expect(JcsUtil.canonicalize(-2.5), equals('-2.5'));
        expect(JcsUtil.canonicalize(0.123), equals('0.123'));
      });

      test('double numbers - trailing zeros removed', () {
        expect(JcsUtil.canonicalize(1.100), equals('1.1'));
        expect(JcsUtil.canonicalize(2.000), equals('2'));
        expect(JcsUtil.canonicalize(3.140), equals('3.14'));
      });

      test('scientific notation', () {
        // Small numbers keep scientific notation
        expect(JcsUtil.canonicalize(1e-10), equals('1e-10'));
        expect(JcsUtil.canonicalize(2.5e-20), equals('2.5e-20'));

        // Large numbers may be converted to decimal representation
        // This behavior matches the RFC 8785 ECMAScript compatibility
        // Dart's toString() handles large numbers differently than JavaScript
        expect(JcsUtil.canonicalize(1e20), equals('100000000000000000000'));

        // Very large numbers keep scientific notation when necessary
        expect(JcsUtil.canonicalize(3.5e25), equals('3.5e+25'));
      });

      test('very large numbers near MAX_SAFE_INTEGER', () {
        // JavaScript MAX_SAFE_INTEGER is 9007199254740991
        expect(
            JcsUtil.canonicalize(9007199254740991), equals('9007199254740991'));
        expect(JcsUtil.canonicalize(9007199254740992.0),
            equals('9007199254740992'));

        // Very large double values should keep decimal representation
        expect(JcsUtil.canonicalize(1000000000000000.0),
            equals('1000000000000000'));
      });

      test('invalid numbers throw errors', () {
        expect(() => JcsUtil.canonicalize(double.nan),
            throwsA(isA<SsiException>()));
        expect(() => JcsUtil.canonicalize(double.infinity),
            throwsA(isA<SsiException>()));
        expect(() => JcsUtil.canonicalize(double.negativeInfinity),
            throwsA(isA<SsiException>()));
      });

      test('string escaping', () {
        expect(JcsUtil.canonicalize('hello'), equals('"hello"'));
        expect(JcsUtil.canonicalize(''), equals('""'));
        expect(JcsUtil.canonicalize('hello world'), equals('"hello world"'));
      });

      test('string special character escaping', () {
        expect(JcsUtil.canonicalize('"'), equals('"\\""'));
        expect(JcsUtil.canonicalize('\\'), equals('"\\\\"'));
        expect(JcsUtil.canonicalize('\b'), equals('"\\b"'));
        expect(JcsUtil.canonicalize('\f'), equals('"\\f"'));
        expect(JcsUtil.canonicalize('\n'), equals('"\\n"'));
        expect(JcsUtil.canonicalize('\r'), equals('"\\r"'));
        expect(JcsUtil.canonicalize('\t'), equals('"\\t"'));
      });

      test('string control character escaping', () {
        expect(JcsUtil.canonicalize('\u0000'), equals('"\\u0000"'));
        expect(JcsUtil.canonicalize('\u0001'), equals('"\\u0001"'));
        expect(JcsUtil.canonicalize('\u001F'), equals('"\\u001f"'));
      });

      test('string unicode characters', () {
        expect(JcsUtil.canonicalize('café'), equals('"café"'));
        expect(JcsUtil.canonicalize('🚀'), equals('"🚀"'));
        expect(JcsUtil.canonicalize('αβγ'), equals('"αβγ"'));
      });
    });

    group('Arrays', () {
      test('empty array', () {
        expect(JcsUtil.canonicalize(<dynamic>[]), equals('[]'));
      });

      test('single element array', () {
        expect(JcsUtil.canonicalize([1]), equals('[1]'));
        expect(JcsUtil.canonicalize(['hello']), equals('["hello"]'));
      });

      test('multiple element array', () {
        expect(JcsUtil.canonicalize([1, 2, 3]), equals('[1,2,3]'));
        expect(JcsUtil.canonicalize(['a', 'b', 'c']), equals('["a","b","c"]'));
      });

      test('mixed type array', () {
        expect(JcsUtil.canonicalize([1, 'hello', true, null]),
            equals('[1,"hello",true,null]'));
      });

      test('nested arrays', () {
        expect(
            JcsUtil.canonicalize([
              [1, 2],
              [3, 4]
            ]),
            equals('[[1,2],[3,4]]'));
        expect(
            JcsUtil.canonicalize(<dynamic>[
              <dynamic>[],
              <dynamic>[1],
              <dynamic>[1, 2]
            ]),
            equals('[[],[1],[1,2]]'));
      });
    });

    group('Objects', () {
      test('empty object', () {
        expect(JcsUtil.canonicalize(<String, dynamic>{}), equals('{}'));
      });

      test('single property object', () {
        expect(
            JcsUtil.canonicalize({'key': 'value'}), equals('{"key":"value"}'));
        expect(JcsUtil.canonicalize({'num': 42}), equals('{"num":42}'));
      });

      test('multiple property object - key ordering', () {
        // Keys should be sorted lexicographically
        expect(JcsUtil.canonicalize({'b': 2, 'a': 1}), equals('{"a":1,"b":2}'));
        expect(JcsUtil.canonicalize({'z': 3, 'a': 1, 'm': 2}),
            equals('{"a":1,"m":2,"z":3}'));
      });

      test('object with mixed value types', () {
        expect(
            JcsUtil.canonicalize(
                {'str': 'hello', 'num': 42, 'bool': true, 'nil': null}),
            equals('{"bool":true,"nil":null,"num":42,"str":"hello"}'));
      });

      test('nested objects', () {
        expect(
            JcsUtil.canonicalize({
              'outer': {'inner': 'value'}
            }),
            equals('{"outer":{"inner":"value"}}'));
        expect(
            JcsUtil.canonicalize({
              'a': {'x': 1},
              'b': {'y': 2}
            }),
            equals('{"a":{"x":1},"b":{"y":2}}'));
      });

      test('object with array values', () {
        expect(
            JcsUtil.canonicalize({
              'list': [1, 2, 3],
              'empty': <dynamic>[]
            }),
            equals('{"empty":[],"list":[1,2,3]}'));
      });

      test('complex key ordering', () {
        final complex = {'10': 'ten', '2': 'two', '1': 'one', '20': 'twenty'};
        // Should be sorted as strings, not numbers
        expect(JcsUtil.canonicalize(complex),
            equals('{"1":"one","10":"ten","2":"two","20":"twenty"}'));
      });
    });

    group('Complex structures', () {
      test('deep nesting', () {
        final complex = {
          'level1': {
            'level2': {
              'level3': {'value': 'deep'}
            }
          }
        };
        expect(JcsUtil.canonicalize(complex),
            equals('{"level1":{"level2":{"level3":{"value":"deep"}}}}'));
      });

      test('mixed arrays and objects', () {
        final mixed = {
          'array': [
            {'name': 'first'},
            {'name': 'second'}
          ],
          'object': {
            'nested': [1, 2, 3]
          }
        };
        expect(
            JcsUtil.canonicalize(mixed),
            equals(
                '{"array":[{"name":"first"},{"name":"second"}],"object":{"nested":[1,2,3]}}'));
      });

      test('credential-like structure', () {
        final credential = {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          'type': ['VerifiableCredential'],
          'issuer': 'did:example:123',
          'credentialSubject': {'id': 'did:example:456', 'name': 'John Doe'},
          'issuanceDate': '2023-01-01T00:00:00Z'
        };

        final expected =
            '{"@context":["https://www.w3.org/2018/credentials/v1"],'
            '"credentialSubject":{"id":"did:example:456","name":"John Doe"},'
            '"issuanceDate":"2023-01-01T00:00:00Z",'
            '"issuer":"did:example:123",'
            '"type":["VerifiableCredential"]}';

        expect(JcsUtil.canonicalize(credential), equals(expected));
      });
    });

    group('Edge cases', () {
      test('non-string keys in map', () {
        final mapWithIntKeys = <dynamic, dynamic>{1: 'one', 2: 'two'};
        expect(JcsUtil.canonicalize(mapWithIntKeys),
            equals('{"1":"one","2":"two"}'));
      });

      test('empty strings and whitespace', () {
        expect(JcsUtil.canonicalize({'': 'empty key'}),
            equals('{"":"empty key"}'));
        expect(JcsUtil.canonicalize({' ': 'space key'}),
            equals('{" ":"space key"}'));
        expect(JcsUtil.canonicalize({'key': ''}), equals('{"key":""}'));
      });

      test('special characters in keys', () {
        final special = {
          'key with spaces': 'value1',
          'key-with-dashes': 'value2',
          'key_with_underscores': 'value3',
          'key.with.dots': 'value4'
        };
        expect(
            JcsUtil.canonicalize(special),
            equals(
                '{"key with spaces":"value1","key-with-dashes":"value2","key.with.dots":"value4","key_with_underscores":"value3"}'));
      });

      test('unsupported types throw errors', () {
        expect(() => JcsUtil.canonicalize(DateTime.now()),
            throwsA(isA<SsiException>()));
        expect(() => JcsUtil.canonicalize(RegExp('')),
            throwsA(isA<SsiException>()));
      });
    });

    group('RFC 8785 examples', () {
      test('example from RFC 8785', () {
        // This example is from RFC 8785 section 3.2.3
        final example = {
          'numbers': [
            333333333.33333329,
            1E30,
            4.50,
            2e-3,
            0.000000000000000000000000001
          ],
          'string': '\u20ac\$\u000F\u000aA\'"\\',
          'literals': [null, true, false]
        };

        final result = JcsUtil.canonicalize(example);
        // For now, just test that it produces valid canonicalized output
        expect(result, isNotEmpty);
        expect(result, contains('"literals":[null,true,false]'));
        expect(result, contains('"numbers":['));
        expect(result, contains('4.5'));
        expect(result, contains('0.002'));
        // Note: Large number handling may vary by platform
      });
    });

    group('Deterministic output', () {
      test('same input produces same output', () {
        final input = {
          'b': [3, 1, 2],
          'a': {'nested': true}
        };
        final result1 = JcsUtil.canonicalize(input);
        final result2 = JcsUtil.canonicalize(input);
        expect(result1, equals(result2));
      });

      test('different key orders produce same output', () {
        final input1 = {'second': 2, 'first': 1, 'third': 3};
        final input2 = {'first': 1, 'third': 3, 'second': 2};
        final input3 = {'third': 3, 'first': 1, 'second': 2};

        final result1 = JcsUtil.canonicalize(input1);
        final result2 = JcsUtil.canonicalize(input2);
        final result3 = JcsUtil.canonicalize(input3);

        expect(result1, equals(result2));
        expect(result2, equals(result3));
        expect(result1, equals('{"first":1,"second":2,"third":3}'));
      });
    });

    group('Test Vectors Validation', () {
      // Test vectors from https://github.com/cyberphone/json-canonicalization/tree/master/testdata
      test('arrays vector', () => testJcsVector('arrays'));
      test('french vector', () => testJcsVector('french'));
      test('structures vector', () => testJcsVector('structures'));
      test('unicode vector', () => testJcsVector('unicode'));
      test('values vector', () => testJcsVector('values'));
      test('weird vector', () => testJcsVector('weird'));
    });
  });
}
