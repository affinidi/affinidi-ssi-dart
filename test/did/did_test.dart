import 'package:ssi/src/did/did.dart';
import 'package:test/test.dart';

void main() {
  group('DidUrl', () {
    test('constructs with all fields', () {
      final didUrl = DidUrl(
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

    test('constructs with only required fields', () {
      final didUrl =
          DidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
      expect(didUrl.scheme, 'did');
      expect(didUrl.method, 'foo');
      expect(didUrl.methodSpecificId, 'bar');
      expect(didUrl.path, isNull);
      expect(didUrl.query, isNull);
      expect(didUrl.fragment, isNull);
      expect(didUrl.queryParameters, {});
    });

    test('queryParameters returns empty map if query is null', () {
      final didUrl =
          DidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
      expect(didUrl.queryParameters, {});
    });

    test('fromUrlString throws if not starting with did:', () {
      expect(() => DidUrl.fromUrlString('foo:bar:baz'), throwsFormatException);
    });

    test('fromUrlString throws if missing method or method-specific-id', () {
      expect(() => DidUrl.fromUrlString('did:'), throwsFormatException);
      expect(() => DidUrl.fromUrlString('did:method'), throwsFormatException);
    });

    test('fromUrlString throws if method or method-specific-id is empty', () {
      expect(() => DidUrl.fromUrlString('did::id'), throwsFormatException);
      expect(() => DidUrl.fromUrlString('did:method:'), throwsFormatException);
    });

    test('fromUrlString parses all components', () {
      final url = 'did:foo:bar/path?x=1#frag';
      final didUrl = DidUrl.fromUrlString(url);
      expect(didUrl.scheme, 'did');
      expect(didUrl.method, 'foo');
      expect(didUrl.methodSpecificId, 'bar');
      expect(didUrl.path, '/path');
      expect(didUrl.query, 'x=1');
      expect(didUrl.fragment, 'frag');
      expect(didUrl.queryParameters, {'x': '1'});
    });

    test('toDidString returns base DID', () {
      final didUrl = DidUrl.fromUrlString('did:foo:bar/path?x=1#frag');
      expect(didUrl.toDidString(), 'did:foo:bar');
    });

    test('toDidUrlString returns full string', () {
      final url = 'did:foo:bar/path?x=1#frag';
      final didUrl = DidUrl.fromUrlString(url);
      expect(didUrl.toDidUrlString(), url);
    });

    test('toDidUrlString omits null fields', () {
      final didUrl =
          DidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
      expect(didUrl.toDidUrlString(), 'did:foo:bar');
    });

    test('resolveDid throws UnimplementedError', () async {
      final didUrl =
          DidUrl(scheme: 'did', method: 'foo', methodSpecificId: 'bar');
      expect(() async => await didUrl.resolveDid(),
          throwsA(isA<UnimplementedError>()));
    });
  });
}
