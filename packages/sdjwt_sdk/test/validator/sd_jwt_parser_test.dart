import 'package:sdjwt_sdk/src/base/hasher.dart';
import 'package:sdjwt_sdk/src/models/disclosure.dart';
import 'package:sdjwt_sdk/src/models/sdjwt.dart';
import 'package:test/test.dart';

const issuerJwt =
    'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiT2owY2RSQWVGY0EyY0RVYkxZWjA0ak9PVXMxWnA3UEpRZ2dJaEtVZFA1WSIsIlJWSnZxdktzQzVxOFpyZnB1cHFlLVlIRkFCbW1CcXozYW44S0JRMm1zVzAiLCJYMlJZRXQzZTdiNzhHRnZTaVlqc3ZPZnRyNC1RTnJsX3paSndDZmN5N0d3Il0sIl9zZF9hbGciOiJTSEEtMjU2In0.visXt1OBN099uR23IGWcFA4THnkTJ3ee7wNCJJkHNEsRwIKIVyxWDZHFBO97fX_j2SGiN1kmrqgl3D8bcvgGqg';

String createDisclosure(String salt, String name, dynamic value) {
  return Disclosure.from(
    salt: salt,
    claimName: name,
    claimValue: value,
    hasher: Base64EncodedOutputHasher.base64Sha256,
  ).serialized;
}

void main() {
  final disclosure1 = createDisclosure('salt1', 'name', 'John');
  final disclosure2 = createDisclosure('salt2', 'age', 25);
  final disclosure3 = createDisclosure('salt3', 'city', 'London');

  group('validates SdJwtValidator.validate method', () {
    test('Valid sd-jwt+kb', () {
      final input = '$issuerJwt~$disclosure1~$disclosure2~holder_kb_jwt';
      final result = SdJwt.parse(input);
      expect(result.jwsString, equals(issuerJwt));
      expect(result.disclosures.length, equals(2));
      expect(result.kbString, equals('holder_kb_jwt'));
    });

    test('Valid sd-jwt without kb', () {
      final input = '$issuerJwt~$disclosure1~$disclosure2~';
      final result = SdJwt.parse(input);
      expect(result.jwsString, equals(issuerJwt));
      expect(result.disclosures.length, equals(2));
      expect(result.kbString, equals(null));
    });

    test('Invalid sd-jwt with empty disclosures', () {
      final input = '$issuerJwt~~holder_kb_jwt';
      expect(() => SdJwt.parse(input), throwsException);
    });

    test('Invalid sd-jwt when empty', () {
      expect(() => SdJwt.parse(''), throwsException);
    });

    test('Invalid sd-jwt when only issuer', () {
      expect(() => SdJwt.parse(issuerJwt), throwsException);
    });

    test('Invalid sd-jwt when empty issuer', () {
      expect(() => SdJwt.parse('~$disclosure1~'), throwsException);
    });

    test('valid sd-jwt when issuer with one disclosure', () {
      final result = SdJwt.parse('$issuerJwt~$disclosure1~');
      expect(result.jwsString, equals(issuerJwt));
      expect(result.disclosures.length, equals(1));
      expect(result.kbString, equals(null));
    });

    test('Invalid sd-jwt when ~ is followed by ~', () {
      expect(() => SdJwt.parse('$issuerJwt~$disclosure1~~holder_kb_jwt'),
          throwsException);
    });

    test('Invalid sd-jwt when duplicate disclosures', () {
      expect(
          () =>
              SdJwt.parse('$issuerJwt~$disclosure1~$disclosure1~holder_kb_jwt'),
          throwsException);
    });

    test('Valid sd-jwt with multiple disclosures', () {
      final input =
          '$issuerJwt~$disclosure1~$disclosure2~$disclosure3~holder_kb_jwt';
      final result = SdJwt.parse(input);
      expect(result.jwsString, equals(issuerJwt));
      expect(result.disclosures.length, equals(3));
      expect(result.kbString, equals('holder_kb_jwt'));
    });

    test('valid sd-jwt with padded parts', () {
      expect(
          () => SdJwt.parse(
              '$issuerJwt~ $disclosure1 ~ $disclosure2 ~ holder_kb_jwt'),
          throwsException);
    });
  });
}
