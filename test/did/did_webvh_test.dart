import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ssi/src/did/did_webvh.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:test/test.dart';

void main() {
  group('DidWebVhUrl.fromDid', () {
    test('should parse valid did:webvh with SCID and domain', () {
      final url = DidWebVhUrl.fromDid('did:webvh:scid123:example.com');

      expect(url.scid, equals('scid123'));
      expect(url.uri.host, equals('example.com'));
      expect(url.uri.scheme, equals('https'));
    });

    test('should parse did:webvh with path', () {
      final url = DidWebVhUrl.fromDid('did:webvh:scid456:example.com:api:v1');

      expect(url.scid, equals('scid456'));
      expect(url.uri.host, equals('example.com'));
      expect(url.uri.path, contains('/api/v1'));
    });

    test('should parse did:webvh with encoded port', () {
      final url = DidWebVhUrl.fromDid('did:webvh:scid789:example.com%3A8080');

      expect(url.scid, equals('scid789'));
      expect(url.uri.host, equals('example.com'));
      expect(url.uri.port, equals(8080));
    });

    test('should parse did:webvh with query parameter versionId', () {
      final url =
          DidWebVhUrl.fromDid('did:webvh:scid123:example.com?versionId=v1');

      expect(url.scid, equals('scid123'));
      expect(url.uri.queryParameters['versionId'], equals('v1'));
    });

    test('should parse did:webvh with query parameter versionTime', () {
      final url = DidWebVhUrl.fromDid(
          'did:webvh:scid123:example.com?versionTime=2023-01-01T00:00:00Z');
      // ignore: avoid_print
      // print(url.uri.queryParameters);
      expect(url.scid, equals('scid123'));
      expect(url.uri.queryParameters['versionTime'],
          equals('2023-01-01T00:00:00Z'));
    });

    test('should parse did:webvh with query parameter versionNumber', () {
      final url =
          DidWebVhUrl.fromDid('did:webvh:scid123:example.com?versionNumber=2');

      expect(url.scid, equals('scid123'));
      expect(url.uri.queryParameters['versionNumber'], equals('2'));
    });

    test('should parse did:webvh with fragment', () {
      final url =
          DidWebVhUrl.fromDid('did:webvh:scid123:example.com#some_fragment');

      expect(url.scid, equals('scid123'));
      expect(url.uri.fragment, equals('some_fragment'));
    });

    test('should throw exception for unsupported DID method', () {
      expect(
        () => DidWebVhUrl.fromDid('did:web:example.com'),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Unsupported DID method'),
        )),
      );
    });

    test('should throw exception when multiple version query params provided',
        () {
      expect(
        () => DidWebVhUrl.fromDid(
            'did:webvh:scid123:example.com?versionId=v1&versionNumber=2'),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Only one of versionId, versionTime, or versionNumber'),
        )),
      );
    });

    test('should handle did:webvh with complex path', () {
      final url =
          DidWebVhUrl.fromDid('did:webvh:scid:example.com:path:to:resource');

      expect(url.scid, equals('scid'));
      expect(url.uri.path, contains('/path/to/resource'));
    });
  });

  group('DidWebVhUrl.toDid', () {
    test('should convert URL back to DID string', () {
      const originalDid = 'did:webvh:scid123:example.com';
      final url = DidWebVhUrl.fromDid(originalDid);
      // ignore: avoid_print
      print(url.toDid());

      expect(url.toDid(), equals(originalDid));
    });

    test('should preserve port in DID conversion', () {
      const originalDid = 'did:webvh:scid789:example.com%3A8080';
      final url = DidWebVhUrl.fromDid(originalDid);

      expect(url.toDid(), equals(originalDid));
    });

    test('should preserve path in DID conversion', () {
      const originalDid = 'did:webvh:scid456:example.com:api:v1';
      final url = DidWebVhUrl.fromDid(originalDid);

      expect(url.toDid(), equals(originalDid));
    });
  });

  group('DidWebVhUrl.toJsonLogFileUrl', () {
    test('should generate URL with .well-known for root path', () {
      final url = DidWebVhUrl.fromDid('did:webvh:scid123:example.com');

      expect(url.toJsonLogFileUrl(),
          equals('https://example.com/.well-known/did.jsonl'));
    });

    test('should generate URL with custom path', () {
      final url = DidWebVhUrl.fromDid('did:webvh:scid123:example.com:api');

      expect(url.toJsonLogFileUrl(),
          contains('https://example.com/api/did.jsonl'));
    });

    test('should preserve port in JSON log URL', () {
      final url = DidWebVhUrl.fromDid('did:webvh:scid789:example.com%3A8080');

      expect(url.toJsonLogFileUrl(), contains('https://example.com:8080'));
      expect(url.toJsonLogFileUrl(), endsWith('/did.jsonl'));
    });
  });

  group('DidWebVhUrl.downloadJsonLogFile', () {
    test('should throw SsiException on network error', () async {
      final mockClient = MockClient((request) async {
        return http.Response('mock log data', 300);
      });
      final url = DidWebVhUrl.fromDid(
          'did:webvh:scid123:invalid-domain-that-does-not-exist.com');

      expect(
        () => url.downloadJsonLogFile(mockClient),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'originalMessage',
          contains('HTTP status code: 300 for URL'),
        )),
      );
    });

    test('should throw SsiException on network error', () async {
      final mockClient = MockClient((request) async {
        throw http.ClientException('Failed to connect');
      });
      final url = DidWebVhUrl.fromDid(
          'did:webvh:scid123:invalid-domain-that-does-not-exist.com');

      expect(
          () => url.downloadJsonLogFile(mockClient),
          throwsA(isA<SsiException>().having(
            (e) => e.toString(),
            'message',
            contains('Failed to fetch DIDWebVH JSON Log file '),
          )));
    });

    // Note: Testing successful downloads would require mocking HTTP client
    // or setting up a test server, which is beyond basic unit testing
  });

  group('DidWebVhUrl edge cases', () {
    test('should handle minimum valid DID', () {
      final url = DidWebVhUrl.fromDid('did:webvh:s:e.c');

      expect(url.scid, equals('s'));
      expect(url.uri.host, equals('e.c'));
    });

    test('should handle %2B encoding', () {
      final url =
          DidWebVhUrl.fromDid('did:webvh:scid:example.com:path%2Bwith%2Bplus');

      expect(url.uri.path, contains('/'));
    });
  });
}
