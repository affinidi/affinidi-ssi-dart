import 'package:ssi/src/did/did.dart';
import 'package:test/test.dart';

class TestDidUrl extends DidUrl {
  TestDidUrl({
    required String scheme,
    required String method,
    required String methodSpecificId,
    String? path,
    String? query,
    String? fragment,
  }) : super.internal(
          scheme: scheme,
          method: method,
          methodSpecificId: methodSpecificId,
          path: path,
          query: query,
          fragment: fragment,
        );
}

void main() {
  group('DidUrl', () {
    group('constructor', () {
      test('should set all fields when all provided', () {
        final didUrl = TestDidUrl(
          scheme: 'did',
          method: 'example',
          methodSpecificId: '123',
          path: '/foo',
          query: 'a=1&b=2',
          fragment: 'frag',
        );
        expect(didUrl.scheme, 'did');
        expect(didUrl.method, 'example');
        expect(didUrl.methodSpecificId, '123');
        expect(didUrl.path, '/foo');
        expect(didUrl.query, 'a=1&b=2');
        expect(didUrl.fragment, 'frag');
        expect(didUrl.queryParameters, {'a': '1', 'b': '2'});
      });

      test('should set nullable fields to null when only required provided',
          () {
        final didUrl =
            TestDidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
        expect(didUrl.scheme, 'did');
        expect(didUrl.method, 'foo');
        expect(didUrl.methodSpecificId, 'bar');
        expect(didUrl.path, isNull);
        expect(didUrl.query, isNull);
        expect(didUrl.fragment, isNull);
        expect(didUrl.queryParameters, <String, String>{});
      });
    });

    group('queryParameters', () {
      test('should return empty map when query is null', () {
        final didUrl =
            TestDidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
        expect(didUrl.queryParameters, <String, String>{});
      });
    });

    group('fromUrlString', () {
      test('should throw FormatException when missing did: prefix', () {
        expect(
            () => DidUrl.fromUrlString('foo:bar:baz'), throwsFormatException);
      });

      test(
          'should throw FormatException when missing method or methodSpecificId',
          () {
        expect(() => DidUrl.fromUrlString('did:'), throwsFormatException);
        expect(() => DidUrl.fromUrlString('did:method'), throwsFormatException);
      });

      test(
          'should throw FormatException when method or methodSpecificId is empty',
          () {
        expect(() => DidUrl.fromUrlString('did::id'), throwsFormatException);
        expect(
            () => DidUrl.fromUrlString('did:method:'), throwsFormatException);
      });

      test('should parse all components when valid url', () {
        final url = 'did:foo:bar/path?x=1#frag';
        final parsed = DidUrl.fromUrlString(url);
        expect(parsed.scheme, 'did');
        expect(parsed.method, 'foo');
        expect(parsed.methodSpecificId, 'bar');
        expect(parsed.path, '/path');
        expect(parsed.query, 'x=1');
        expect(parsed.fragment, 'frag');

        final didUrl = TestDidUrl(
          scheme: parsed.scheme,
          method: parsed.method,
          methodSpecificId: parsed.methodSpecificId,
          path: parsed.path,
          query: parsed.query,
          fragment: parsed.fragment,
        );
        expect(didUrl.queryParameters, {'x': '1'});
      });
    });

    group('toDidString', () {
      test('should return base DID without path query or fragment', () {
        final didUrl = TestDidUrl(
          scheme: 'did',
          method: 'foo',
          methodSpecificId: 'bar',
          path: '/path',
          query: 'x=1',
          fragment: 'frag',
        );
        expect(didUrl.toDidString(), 'did:foo:bar');
      });
    });

    group('toDidUrlString', () {
      test('should return full url when all components present', () {
        final didUrl = TestDidUrl(
          scheme: 'did',
          method: 'foo',
          methodSpecificId: 'bar',
          path: '/path',
          query: 'x=1',
          fragment: 'frag',
        );
        expect(didUrl.toDidUrlString(), 'did:foo:bar/path?x=1#frag');
      });

      test('should omit optional parts when null', () {
        final didUrl =
            TestDidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
        expect(didUrl.toDidUrlString(), 'did:foo:bar');
      });
    });

    group('resolveDid', () {
      test('should throw UnimplementedError when called on base class',
          () async {
        final didUrl =
            TestDidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
        expect(() async => await didUrl.resolveDid(),
            throwsA(isA<UnimplementedError>()));
      });
    });
  });
}
