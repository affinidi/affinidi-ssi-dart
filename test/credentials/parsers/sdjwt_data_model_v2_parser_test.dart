import 'package:ssi/src/credentials/parsers/sdjwt_data_model_v2_parser.dart';
import 'package:test/test.dart';

void main() {
  group('SdJwtDataModelV2Parser', () {
    late SdJwtDataModelV2Parser parser;

    setUp(() {
      parser = SdJwtDataModelV2Parser();
    });

    group('canParse', () {
      test('returns true for non-empty string', () {
        expect(parser.canParse('header.body.signature'), isTrue);
      });

      test('returns false for empty string', () {
        expect(parser.canParse(''), isFalse);
      });

      test('returns false for whitespace string', () {
        expect(parser.canParse('   '), isFalse);
      });
    });

    group('parse', () {
      test('successfully parses valid SD-JWT with VC 2.0 payload', () {
        //todo: add test body

      });

      test('throws when SD-JWT is invalid', () {
        expect(
          () => parser.parse('an invalid token'),
          throwsA(isA<Exception>()),
        );
      });

      test('throws when VC payload is invalid', () {
        //todo: add test body
      });

      test('throws when VC payload is missing required properties', () {
        //todo: add test body
      });
    });
  });
}
