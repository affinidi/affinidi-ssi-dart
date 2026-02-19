// ignore_for_file: avoid_print

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ssi/src/did/did_webvh.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidWebVh.parse', () {
    test('should parse valid did:webvh with SCID and domain', () {
      final didWebVh1 = DidWebVh.parse('did:webvh:scid123:example.com');

      expect(didWebVh1.scid, equals('scid123'));
      expect(didWebVh1.httpsUrl.host, equals('example.com'));
      expect(didWebVh1.scheme, equals('did'));
    });

    test('should parse did:webvh with path', () {
      final didWebVh1 = DidWebVh.parse('did:webvh:scid456:example.com:api:v1');

      expect(didWebVh1.scid, equals('scid456'));
      expect(didWebVh1.httpsUrl.host, equals('example.com'));
      expect(didWebVh1.httpsUrl.path, contains('/api/v1'));
    });

    test('should parse did:webvh with encoded port', () {
      final didWebVh1 = DidWebVh.parse('did:webvh:scid789:example.com%3A8080');

      expect(didWebVh1.scid, equals('scid789'));
      expect(didWebVh1.httpsUrl.host, equals('example.com'));
      expect(didWebVh1.httpsUrl.port, equals(8080));
    });

    test('should parse did:webvh with query parameter versionId', () {
      final didWebVh1 =
          DidWebVh.parse('did:webvh:scid123:example.com?versionId=v1');

      expect(didWebVh1.scid, equals('scid123'));
      expect(didWebVh1.httpsUrl.queryParameters['versionId'], equals('v1'));
    });

    test('should parse did:webvh with query parameter versionTime', () {
      final didWebVh1 = DidWebVh.parse(
          'did:webvh:scid123:example.com?versionTime=2023-01-01T00:00:00Z');
      expect(didWebVh1.scid, equals('scid123'));
      expect(didWebVh1.httpsUrl.queryParameters['versionTime'],
          equals('2023-01-01T00:00:00Z'));
    });

    test('should parse did:webvh with query parameter versionNumber', () {
      final didWebVh1 =
          DidWebVh.parse('did:webvh:scid123:example.com?versionNumber=2');

      expect(didWebVh1.scid, equals('scid123'));
      expect(didWebVh1.httpsUrl.queryParameters['versionNumber'], equals('2'));
    });

    test('should parse did:webvh with fragment', () {
      final didWebVh1 =
          DidWebVh.parse('did:webvh:scid123:example.com#some_fragment');

      expect(didWebVh1.scid, equals('scid123'));
      expect(didWebVh1.httpsUrl.fragment, equals('some_fragment'));
    });

    test('should throw exception for unsupported DID method', () {
      expect(
        () => DidWebVh.parse('did:web:example.com'),
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
        () => DidWebVh.parse(
            'did:webvh:scid123:example.com?versionId=v1&versionNumber=2'),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Only one of versionId, versionTime, or versionNumber'),
        )),
      );
    });

    test('should handle did:webvh with complex path', () {
      final url = DidWebVh.parse('did:webvh:scid:example.com:path:to:resource');

      expect(url.scid, equals('scid'));
      expect(url.httpsUrl.path, contains('/path/to/resource'));
    });
  });

  group('DidWebVh.toString', () {
    test('should convert URL back to DID string', () {
      const originalDidString = 'did:webvh:scid123:example.com';
      final didWebVh1 = DidWebVh.parse(originalDidString);

      expect(didWebVh1.toString(), equals(originalDidString));
    });

    test('should preserve port in DID conversion', () {
      const originalDidString = 'did:webvh:scid789:example.com%3A8080';
      final didWebVh1 = DidWebVh.parse(originalDidString);

      expect(didWebVh1.toString(), equals(originalDidString));
    });

    test('should preserve path in DID conversion', () {
      const originalDidString = 'did:webvh:scid456:example.com:api:v1';
      final didWebVh1 = DidWebVh.parse(originalDidString);

      expect(didWebVh1.toString(), equals(originalDidString));
    });
  });

  group('DidWebVh.jsonLogFileHttpsUrlString', () {
    test('should generate URL with .well-known for root path', () {
      final didWebVh1 = DidWebVh.parse('did:webvh:scid123:example.com');

      expect(didWebVh1.jsonLogFileHttpsUrlString,
          equals('https://example.com/.well-known/did.jsonl'));
    });

    test('should generate URL with custom path', () {
      final didWebVh1 = DidWebVh.parse('did:webvh:scid123:example.com:api');

      expect(didWebVh1.jsonLogFileHttpsUrlString,
          contains('https://example.com/api/did.jsonl'));
    });

    test('should preserve port in JSON log URL', () {
      final didWebVh1 = DidWebVh.parse('did:webvh:scid789:example.com%3A8080');

      expect(didWebVh1.jsonLogFileHttpsUrlString,
          contains('https://example.com:8080'));
      expect(didWebVh1.jsonLogFileHttpsUrlString, endsWith('/did.jsonl'));
    });
  });

  group('DidWebVh.downloadWebVhLog', () {
    test('should throw SsiException on network error', () async {
      final mockClient = MockClient((request) async {
        return http.Response('mock log data', 300);
      });
      final url = DidWebVh.parse(
          'did:webvh:scid123:invalid-domain-that-does-not-exist.com');

      expect(
        () => url.downloadWebVhLog(mockClient),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('HTTP 300 error fetching'),
        )),
      );
    });

    test('should throw SsiException on network error', () async {
      final mockClient = MockClient((request) async {
        throw http.ClientException('Failed to connect');
      });
      final url = DidWebVh.parse(
          'did:webvh:scid123:invalid-domain-that-does-not-exist.com');

      expect(
          () => url.downloadWebVhLog(mockClient),
          throwsA(isA<SsiException>().having(
            (e) => e.toString(),
            'message',
            contains('Failed to fetch'),
          )));
    });
  });

  group('DidWebVh edge cases', () {
    test('should handle minimum valid DID', () {
      final url = DidWebVh.parse('did:webvh:s:e.c');

      expect(url.scid, equals('s'));
      expect(url.httpsUrl.host, equals('e.c'));
    });

    test('should handle %2B encoding', () {
      final url =
          DidWebVh.parse('did:webvh:scid:example.com:path%2Bwith%2Bplus');

      expect(url.httpsUrl.path, contains('/'));
    });
  });

  group('DidWebVhLogEntry', () {
    test('should parse valid log entry from JSON', () {
      final json = {
        'versionId': '1-QmHash123',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': {
          'method': 'did:webvh:1.0',
          'scid': 'QmScid123',
          'updateKeys': ['z6MkKey1', 'z6MkKey2'],
          'portable': true,
          'ttl': 3600,
        },
        'state': {
          '@context': ['https://www.w3.org/ns/did/v1'],
          'id': 'did:webvh:QmScid123:example.com',
        },
        'proof': [
          {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'eddsa-jcs-2022',
            'proofPurpose': 'assertionMethod',
          }
        ],
      };

      final entry = DidWebVhLogEntry.fromJson(json);

      expect(entry.versionId, equals('1-QmHash123'));
      expect(entry.versionTime, equals(DateTime.parse('2024-04-05T07:32:58Z')));
      expect(entry.parameters.method, equals('did:webvh:1.0'));
      expect(entry.parameters.scid, equals('QmScid123'));
      expect(entry.parameters.updateKeys, equals(['z6MkKey1', 'z6MkKey2']));
      expect(entry.parameters.portable, equals(true));
      expect(entry.parameters.ttl, equals(3600));
      expect(entry.state.id, equals('did:webvh:QmScid123:example.com'));
      expect(entry.proof.length, equals(1));
      expect(entry.proof[0]['type'], equals('DataIntegrityProof'));
    });

    test('should extract version number from versionId', () {
      final json = {
        'versionId': '42-QmHash123',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": ["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      final entry = DidWebVhLogEntry.fromJson(json);

      expect(entry.versionNumber, equals(42));
    });

    test('should handle optional parameters', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': {
          'method': 'did:webvh:1.0',
        },
        'state': {
          "@context": ["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      final entry = DidWebVhLogEntry.fromJson(json);

      expect(entry.parameters.method, equals('did:webvh:1.0'));
      expect(entry.parameters.scid, isNull);
      expect(entry.parameters.updateKeys, isNull);
      expect(entry.parameters.nextKeyHashes, isNull);
      expect(entry.parameters.witness, isNull);
      expect(entry.parameters.watchers, isNull);
      expect(entry.parameters.portable, isNull);
      expect(entry.parameters.deactivated, isNull);
      expect(entry.parameters.ttl, isNull);
    });

    test('should parse witness parameter as Map', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': {
          'method': 'did:webvh:1.0',
          'witness': {
            'threshold': 2,
            'witnesses': [
              {'id': 'did:key:z6Mk1'},
              {'id': 'did:key:z6Mk2'},
            ],
          },
        },
        'state': {
          "@context": ["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      final entry = DidWebVhLogEntry.fromJson(json);

      expect(entry.parameters.witness, isA<Map<String, dynamic>>());
      expect(entry.parameters.witness?['threshold'], equals(2));
      expect(entry.parameters.witness?['witnesses'], isA<List>());
    });

    test('should parse watchers as List of Strings', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': {
          'method': 'did:webvh:1.0',
          'watchers': [
            'https://watcher1.example.com',
            'https://watcher2.example.com',
          ],
        },
        'state': {
          "@context": ["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      final entry = DidWebVhLogEntry.fromJson(json);

      expect(entry.parameters.watchers, isA<List<String>>());
      expect(entry.parameters.watchers?.length, equals(2));
      expect(entry.parameters.watchers?[0],
          equals('https://watcher1.example.com'));
    });

    test('should parse multiple proofs', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': [
          {'type': 'DataIntegrityProof', 'proofValue': 'z5V1'},
          {'type': 'DataIntegrityProof', 'proofValue': 'z5V2'},
        ],
      };

      final entry = DidWebVhLogEntry.fromJson(json);

      expect(entry.proof.length, equals(2));
      expect(entry.proof[0]['proofValue'], equals('z5V1'));
      expect(entry.proof[1]['proofValue'], equals('z5V2'));
    });

    test('should throw error when versionId is missing', () {
      final json = {
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<TypeError>()),
      );
    });

    test('should throw error when versionTime is missing', () {
      final json = {
        'versionId': '1-QmHash',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<TypeError>()),
      );
    });

    test('should throw error when parameters is missing', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<TypeError>()),
      );
    });

    test('should throw error when state is missing', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': <dynamic, dynamic>{},
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<TypeError>()),
      );
    });

    test('should throw error when proof is missing', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58Z',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<TypeError>()),
      );
    });

    test('should throw SsiException when versionTime has invalid format', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': 'invalid-datetime-format',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<SsiDidResolutionException>().having(
          (e) => e.toString(),
          'message',
          contains('Invalid DID WebVh Log Entry versionTime format.'),
        )),
      );
    });

    test('should throw SsiException when versionTime is missing timezone', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58',
        'parameters': <dynamic, dynamic>{},
        'state': {
          "@context": <String>["https://www.w3.org/ns/did/v1"],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<SsiDidResolutionException>().having(
          (e) => e.toString(),
          'message',
          contains('Invalid DID WebVh Log Entry versionTime format.'),
        )),
      );
    });
  });

  group('DidWebVhLog', () {
    test('should parse valid JSON Lines with single entry', () {
      final jsonLines = '''
{"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0"},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(1));
      expect(log.entries[0].versionId, equals('1-QmHash'));
      expect(log.entries[0].versionNumber, equals(1));
    });

    test('should parse multiple log entries', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid"},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[]}
{"versionId":"3-QmHash3","versionTime":"2024-04-05T09:00:00Z","parameters":{},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(3));
      expect(log.entries[0].versionNumber, equals(1));
      expect(log.entries[1].versionNumber, equals(2));
      expect(log.entries[2].versionNumber, equals(3));
      expect(log.entries[1].parameters.method, isNull);
      expect(log.entries[2].parameters.method, isNull);
    });

    test('should handle empty lines in JSON Lines', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0"},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}

{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}

''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(log.entries[0].versionTime,
          equals(DateTime.parse('2024-04-05T07:32:58Z')));
      expect(log.entries[1].versionTime,
          equals(DateTime.parse('2024-04-05T08:00:00Z')));
    });

    test('should parse log with complete parameters', () {
      final jsonLines = '''
{"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHash1"],"witness":{"threshold":1,"witnesses":[{"id":"did:key:z6Mk1"}]},"watchers":["https://watcher.com"],"portable":true,"deactivated":false,"ttl":7200},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(1));
      final entry = log.entries[0];
      expect(entry.parameters.method, equals('did:webvh:1.0'));
      expect(entry.parameters.scid, equals('QmScid'));
      expect(entry.parameters.updateKeys?.length, equals(1));
      expect(entry.parameters.nextKeyHashes?.length, equals(1));
      expect(entry.parameters.witness?['threshold'], equals(1));
      expect(entry.parameters.watchers?.length, equals(1));
      expect(entry.parameters.portable, equals(true));
      expect(entry.parameters.deactivated, equals(false));
      expect(entry.parameters.ttl, equals(7200));
    });

    test('should handle log with deactivated DID', () {
      final jsonLines = '''
{"versionId":"5-QmHash","versionTime":"2024-04-05T10:00:00Z","parameters":{"deactivated":true},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(1));
      expect(log.entries[0].parameters.deactivated, equals(true));
    });

    test('should preserve order of entries', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0"},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
{"versionId":"2-QmHash2","versionTime":"2024-02-01T00:00:00Z","parameters":{},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
{"versionId":"3-QmHash3","versionTime":"2024-03-01T00:00:00Z","parameters":{},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries[0].versionTime,
          equals(DateTime.parse('2024-01-01T00:00:00Z')));
      expect(log.entries[1].versionTime,
          equals(DateTime.parse('2024-02-01T00:00:00Z')));
      expect(log.entries[2].versionTime,
          equals(DateTime.parse('2024-03-01T00:00:00Z')));
    });

    test('should parse empty JSON Lines as empty log', () {
      final jsonLines = '';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(0));
    });

    test('should handle whitespace-only lines', () {
      final jsonLines = '''
{"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0"},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
   
	
{"versionId":"2-QmHash","versionTime":"2024-04-05T08:00:00Z","parameters":{},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:scid:example.com"},"proof":[]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(log.entries[0].versionTime,
          equals(DateTime.parse('2024-04-05T07:32:58Z')));
      expect(log.entries[1].versionTime,
          equals(DateTime.parse('2024-04-05T08:00:00Z')));
    });

    test(
        'should throw SsiException when verify is called with unsupported webvh version',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:2.0","scid":"QmScid123","updateKeys":["z6MkKey1"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expectLater(
        log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Only did:webvh:1.0 method is supported'),
        )),
      );
    });

    test(
        'should throw SsiException when verify is called with non-sequential version numbers - 4',
        () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"3-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expectLater(
        log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Invalid version number sequence'),
        )),
      );
    });

    test(
        'should throw SsiException when verify is called with non-sequential version numbers - 3',
        () {
      final jsonLines = '''
{"versionId":"0-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"3-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Invalid version number sequence'),
        )),
      );
    });

    test(
        'should throw SsiException when verify is called with non-sequential version numbers - 1',
        () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"0-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Invalid version number sequence'),
        )),
      );
    });

    test(
        'should throw SsiException when verify is called with non-sequential version numbers - 2',
        () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"1-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Invalid version number sequence'),
        )),
      );
    });

    test(
        'should throw SsiException when verify is called with non-ascending versionTime values',
        () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T22:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Version timestamps must be strictly ascending'),
        )),
      );
    });

    test(
        'should throw SsiException when deactivation is not the last version in log',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {"deactivated": true}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
{"versionId": "3-QmSomeHash", "versionTime": "2026-02-02T13:39:31Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify(
            {'skipHashEntryVerification': true, 'skipProofVerification': true}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('No updates allowed after deactivation'),
        )),
      );
    });

    test(
        'should throw SsiException when entry hash does not match with hash of entry content',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-QmInvalidHashThatDoesNotMatch", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('EntryHash verification failed'),
        )),
      );
    });

    test(
        'should throw SsiException when method parameter is missing in the first version',
        () {
      final jsonLines = '''
{"versionId": "1-QmHash1", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"scid": "QmScid123", "updateKeys": ["z6MkKey1"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmScid123:example.com"}, "proof": []}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Note: _parameterMethodMustBeVersion1 is called before _parameterMethodMustExistInFirstVersion
      // So when method is null, the version check fails first
      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Only did:webvh:1.0 method is supported'),
        )),
      );
    });

    test(
        'should throw SsiException when scid parameter is missing in the first version',
        () {
      final jsonLines = '''
{"versionId": "1-QmHash1", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"method": "did:webvh:1.0", "updateKeys": ["z6MkKey1"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:example.com"}, "proof": []}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('First log entry must contain "scid" parameter'),
        )),
      );
    });

    test(
        'should throw SsiException when updateKeys parameter is missing in the first version',
        () {
      final jsonLines = '''
{"versionId": "1-QmHash1", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"method": "did:webvh:1.0", "scid": "QmScid123"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmScid123:example.com"}, "proof": []}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('First log entry must contain "updateKeys" parameter'),
        )),
      );
    });

    test(
        'should throw SsiException when scid parameter does not match with hash of first entry',
        () {
      final jsonLines = '''
{"versionId": "1-QmHash1", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"method": "did:webvh:1.0", "scid": "QmWrongScidThatDoesNotMatch", "updateKeys": ["z6MkKey1"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmWrongScidThatDoesNotMatch:example.com"}, "proof": []}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('SCID verification failed'),
        )),
      );
    });

    test(
        'should throw SsiException when scid parameter exists in later versions',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-QmHash2", "versionTime": "2026-02-02T13:39:30Z", "parameters": {"scid": "QmShouldNotBeHere"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('SCID parameter must only appear in first log entry'),
        )),
      );
    });

    test(
        'should throw SsiException when portable parameter is true in later versions',
        () {
      // First entry without portable parameter (defaults to false)
      // Second entry tries to set portable to true (not allowed)
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-QmHash2", "versionTime": "2026-02-02T13:39:30Z", "parameters": {"portable": true}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains(
              'Portable parameter can only be set to true in the first entry'),
        )),
      );
    });

    // Pre-rotation validation tests
    test('should validate pre-rotation with test data', () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);
      expect(log.entries.length, equals(2));

      expect(log.entries[0].parameters.nextKeyHashes,
          contains('QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx'));
      expect(log.entries[1].parameters.updateKeys,
          contains('z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7'));

      expect(() => log.verify({}), returnsNormally);
    });

    test('should parse log with nextKeyHashes in parameters', () {
      final jsonLines = '''
{"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHash1","QmHash2","QmHash3"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(1));
      expect(log.entries[0].parameters.nextKeyHashes?.length, equals(3));
      expect(log.entries[0].parameters.nextKeyHashes?[0], equals('QmHash1'));
      expect(log.entries[0].parameters.nextKeyHashes?[1], equals('QmHash2'));
      expect(log.entries[0].parameters.nextKeyHashes?[2], equals('QmHash3'));
    });

    test('should parse log with empty nextKeyHashes (deactivates pre-rotation)',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":[]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(1));
      expect(log.entries[0].parameters.nextKeyHashes, isEmpty);
    });

    test('should parse log where pre-rotation is deactivated then reactivated',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHash1","QmHash2"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"nextKeyHashes":[]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"3-QmHash3","versionTime":"2024-04-05T09:00:00Z","parameters":{"nextKeyHashes":["QmHash3"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(3));
      expect(log.entries[0].parameters.nextKeyHashes, hasLength(2));
      expect(log.entries[1].parameters.nextKeyHashes, isEmpty); // Deactivated
      expect(
          log.entries[2].parameters.nextKeyHashes, hasLength(1)); // Reactivated
    });

    test('should demonstrate pre-rotation with multiple keys', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1","z6MkKey2"],"nextKeyHashes":["QmHash1","QmHash2","QmHash3"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKey3"],"nextKeyHashes":["QmHash4","QmHash5"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(log.entries[0].parameters.updateKeys, hasLength(2));
      expect(log.entries[0].parameters.nextKeyHashes, hasLength(3));
      expect(log.entries[1].parameters.updateKeys, hasLength(1));
      expect(log.entries[1].parameters.nextKeyHashes, hasLength(2));
    });

    test('should parse log with nextKeyHashes inheritance', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHash1","QmHash2"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKey2"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(log.entries[0].parameters.nextKeyHashes, hasLength(2));
      expect(log.entries[1].parameters.nextKeyHashes, isNull);
    });

    test(
        'should throw SsiException when updateKey is not pre-committed in nextKeyHashes',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHashA","QmHashB"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKeyUnauthorized"],"nextKeyHashes":["QmHashC"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains(
              'Pre-rotation: updateKey z6MkKeyUnauthorized in entry 2 is not present as a hash in previous entry\'s nextKeyHashes'),
        )),
      );
    });

    test(
        'should throw SsiException when nextKeyHashes is missing while pre-rotation is active',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHashA","QmHashB"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKey2"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains(
              'Pre-rotation active: nextKeyHashes must be present in entry 2'),
        )),
      );
    });

    test(
        'should throw SsiException when updateKeys is missing while pre-rotation is active',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHashA","QmHashB"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"nextKeyHashes":["QmHashC"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains(
              'Pre-rotation active: updateKeys must be present in entry 2'),
        )),
      );
    });

    test(
        'should throw SsiException when multiple updateKeys have hashes not in nextKeyHashes',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHashA"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKey2","z6MkKey3","z6MkKey4"],"nextKeyHashes":["QmHashB"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains(
              'is not present as a hash in previous entry\'s nextKeyHashes'),
        )),
      );
    });

    test(
        'should throw SsiException when pre-rotation constraint violated with empty updateKeys',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHashA"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":[],"nextKeyHashes":["QmHashB"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true,
          'skipDidDocumentValidation': true,
        }),
        returnsNormally,
      );
    });

    test('should validate pre-rotation chain across multiple key rotations',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmHashForKey2"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKey2"],"nextKeyHashes":["QmHashForKey3"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"3-QmHash3","versionTime":"2024-04-05T09:00:00Z","parameters":{"updateKeys":["z6MkKeyWrong"],"nextKeyHashes":["QmHashForKey4"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          allOf([
            contains('Pre-rotation'),
            contains(
                'is not present as a hash in previous entry\'s nextKeyHashes'),
          ]),
        )),
      );
    });

    test(
        'should throw SsiException when first entry has nextKeyHashes but second entry violates it',
        () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2024-04-05T07:32:58Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid","updateKeys":["z6MkKey1"],"nextKeyHashes":["QmOnlyThisHashAllowed"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2024-04-05T08:00:00Z","parameters":{"updateKeys":["z6MkKeyNotInNextKeyHashes"],"nextKeyHashes":["QmSomeOtherHash"]},"state":{"@context": ["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipAllProofRelatedVerification': true,
          'skipScidVerification': true
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains(
              'Pre-rotation: updateKey z6MkKeyNotInNextKeyHashes in entry 2 is not present as a hash in previous entry\'s nextKeyHashes'),
        )),
      );
    });

    test('should validate real data: pre-rotation key rotation cycle', () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Verify key rotation: entry 2 uses a key that was pre-committed in entry 1
      final entry1NextKeyHashes = log.entries[0].parameters.nextKeyHashes!;
      final entry2UpdateKeys = log.entries[1].parameters.updateKeys!;
      final entry2NextKeyHashes = log.entries[1].parameters.nextKeyHashes!;

      expect(entry1NextKeyHashes, hasLength(3));
      expect(entry2UpdateKeys, hasLength(1));
      expect(entry2NextKeyHashes, hasLength(3));
      expect(entry1NextKeyHashes,
          contains('QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx'));
      expect(entry2UpdateKeys,
          contains('z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7'));
      expect(entry2NextKeyHashes,
          contains('QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8'));

      expect(() => log.verify({}), returnsNormally);
    });

    test(
        'should verify log up to specific versionId and return document with that versionId',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://identity.foundation/.well-known/did-configuration/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "authentication": ["did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"], "assertionMethod": ["did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"], "verificationMethod": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F", "controller": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"}], "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#domain", "type": "LinkedDomains", "serviceEndpoint": "https://domain.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
{"versionId": "3-QmXYZ789Hash3Example", "versionTime": "2026-02-02T13:39:31Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service3", "type": "Service3", "serviceEndpoint": "https://service3.example"}], "verificationMethod": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkuXZdvxqN4W1KK4gtBqH2vFJwJ8sUZH6YP9hzN3Zh5Jt2", "controller": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkuXZdvxqN4W1KK4gtBqH2vFJwJ8sUZH6YP9hzN3Zh5Jt2"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:31Z", "proofPurpose": "assertionMethod", "proofValue": "z5ExampleProofValue3"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(3));

      expectLater(
        log.verify({
          'versionId': '2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE',
          'skipHashEntryVerification': true,
          'skipDidDocumentValidation': true,
          'skipProofVerification': true,
        }).then((result) {
          final (didDoc, _, _) = result;
          expect(didDoc.service[0].id, contains('#domain'));
          expect(didDoc.service[0].id, isNot(contains('#service3')));
        }),
        completes,
      );
    });

    test('should throw SsiException when versionId is not found in log', () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({'versionId': '99-QmNonExistentVersionId'}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('not found in log'),
        )),
      );
    });

    test(
        'should throw SsiException when versionId is found but that version is invalid',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-QmInvalidHashForVersion2", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
{"versionId": "3-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:31Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({'versionId': '2-QmInvalidHashForVersion2'}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('EntryHash verification failed'),
        )),
      );
    });

    test(
        'should verify log up to specific versionTime and return last document at or before that time',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service2", "type": "Service2", "serviceEndpoint": "https://service2.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
{"versionId": "3-QmXYZ789Hash3Example", "versionTime": "2026-02-02T13:39:31Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service3", "type": "Service3", "serviceEndpoint": "https://service3.example"}]}, "proof": [{"type": "DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(3));

      expectLater(
        log.verify({
          'versionTime': '2026-02-02T13:39:30Z',
          'skipHashEntryVerification': true,
          'skipDidDocumentValidation': true,
          'skipProofVerification': true,
        }).then((result) {
          final (didDoc, _, _) = result;
          expect(didDoc.service[0].id, contains('#service2'));
        }),
        completes,
      );
    });

    test(
        'should throw SsiException when no entries found at or before versionTime',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service2", "type": "Service2", "serviceEndpoint": "https://service2.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'versionTime': '2026-02-02T13:39:28Z',
          'skipHashEntryVerification': true,
          'skipProofVerification': true,
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('No entries found at or before versionTime'),
        )),
      );
    });

    test(
        'should verify log up to specific versionNumber and return document with that versionNumber',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service2", "type": "Service2", "serviceEndpoint": "https://service2.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
{"versionId": "3-QmXYZ789Hash3Example", "versionTime": "2026-02-02T13:39:31Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service3", "type": "Service3", "serviceEndpoint": "https://service3.example"}]}, "proof": [{"type": "DataIntegrityProof"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(3));

      expectLater(
        log.verify({
          'versionNumber': 2,
          'skipHashEntryVerification': true,
          'skipDidDocumentValidation': true,
          'skipProofVerification': true,
        }).then((result) {
          final (didDoc, _, _) = result;
          expect(didDoc.service[0].id, contains('#service2'));
        }),
        completes,
      );
    });

    test('should throw SsiException when versionNumber is not found in log',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#service2", "type": "Service2", "serviceEndpoint": "https://service2.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({'versionNumber': 99}),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('not found in log'),
        )),
      );
    });

    test('_proofMustBeValid throws if cryptosuite is missing from proof', () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipScidVerification': true,
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Missing required fields'),
        )),
      );
    });

    test('_proofMustBeValid throws if verificationMethod is missing from proof',
        () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipScidVerification': true,
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Missing required fields'),
        )),
      );
    });

    test('_proofMustBeValid throws if proofValue is missing from proof', () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipScidVerification': true,
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Missing required fields'),
        )),
      );
    });

    test('_proofMustBeValid throws if cryptosuite is not supported', () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "unsupported-cryptosuite", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipScidVerification': true,
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Unsupported cryptosuite'),
        )),
      );
    });

    test(
        '_proofMustBeValid throws if signing key is not in authorized updateKeys list',
        () {
      // The verificationMethod uses z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV
      // but updateKeys only contains z6MkDifferentKeyNotInUpdateKeys
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkDifferentKeyNotInUpdateKeys"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipScidVerification': true,
          'skipProofVerification': true,
        }),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('is not in authorized updateKeys list'),
        )),
      );
    });

    test('_proofMustBeValid throws if signature verification fails', () {
      // Valid structure but proofValue is tampered (last char changed from 6 to 7)
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH7"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(
        () => log.verify({
          'skipHashEntryVerification': true,
          'skipScidVerification': true,
        }),
        throwsA(isA<SsiDidResolutionException>().having(
          (e) => e.toString(),
          'message',
          contains('Signature verification failed'),
        )),
      );
    });

    test('_addDefaultServicesToDidDocument adds #whois service if not existing',
        () async {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      final (didDoc, _, _) = await log.verify();

      // Check that #whois service was added
      final whoisService = didDoc.service.firstWhere(
        (s) => s.id == '#whois',
        orElse: () => throw Exception('#whois service not found'),
      );

      expect(whoisService.type.toString(),
          contains('LinkedVerifiablePresentation'));
      final endpoint = whoisService.serviceEndpoint as StringEndpoint;
      expect(
          endpoint.url, equals('https://domain.example/.well-known/whois.vp'));
    });

    test('_addDefaultServicesToDidDocument adds #files service if not existing',
        () async {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      final (didDoc, _, _) = await log.verify();

      // Check that #files service was added
      final filesService = didDoc.service.firstWhere(
        (s) => s.id == '#files',
        orElse: () => throw Exception('#files service not found'),
      );

      expect(filesService.type.toString(), contains('relativeRef'));
      final endpoint = filesService.serviceEndpoint as StringEndpoint;
      expect(endpoint.url, equals('https://domain.example'));
    });

    test(
        '_addDefaultServicesToDidDocument does not add duplicates if default services exist',
        () async {
      // DID document already includes #whois and #files services
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "service": [{"id": "#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://custom.example/whois.vp"}, {"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#files", "type": "relativeRef", "serviceEndpoint": "https://custom.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      final (didDoc, _, _) = await log.verify({
        'skipHashEntryVerification': true,
        'skipScidVerification': true,
        'skipAllProofRelatedVerification': true,
      });

      // Verify that only 2 services exist (no duplicates were added)
      expect(didDoc.service.length, equals(2));

      // Verify the services are the original ones
      final whoisService = didDoc.service.firstWhere((s) => s.id == '#whois');
      final whoisEndpoint = whoisService.serviceEndpoint as StringEndpoint;
      expect(whoisEndpoint.url, equals('https://custom.example/whois.vp'));

      final filesService = didDoc.service.firstWhere((s) =>
          s.id ==
          'did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#files');
      final filesEndpoint = filesService.serviceEndpoint as StringEndpoint;
      expect(filesEndpoint.url, equals('https://custom.example'));
    });
  });

  group('temp tests', () {
    test('temp test 1 - verify jsonlines from affinidi', () async {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(log.entries[0].versionTime,
          equals(DateTime.parse('2025-07-13T23:43:58Z')));
      expect(log.entries[1].versionTime,
          equals(DateTime.parse('2025-07-13T23:44:37Z')));

      await log.verify({
          'skipDidDocumentValidation': true,
      });
    });

    test('temp test 2 - verify jsonlines from python script', () async {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://identity.foundation/.well-known/did-configuration/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "authentication": ["did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"], "assertionMethod": ["did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"], "verificationMethod": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F", "controller": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"}], "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#domain", "type": "LinkedDomains", "serviceEndpoint": "https://domain.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(log.entries[0].versionTime,
          equals(DateTime.parse('2026-02-02T13:39:29Z')));
      expect(log.entries[1].versionTime,
          equals(DateTime.parse('2026-02-02T13:39:30Z')));

      await log.verify({
          'skipDidDocumentValidation': true,
      });
    });

    test('temp test 3 - get did from web and verify', () async {
      final did1 =
          'did:webvh:scid123:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:add-did-webvh:example:dids:didwebvh:domain-example';

      // final did2 =
      //     'did:webvh:scid123:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs';

      final didwebvh = DidWebVh.parse(did1);
      final (didDoc, didDocMeta, didResMeta) = await didwebvh.resolveDid({
          'skipDidDocumentValidation': true,
      });
      // print('did url: ${didwebvh.jsonLogFileHttpsUrlString}');
      // print('didDoc: ${didDoc.toString()}');
      // print('didDocMeta: ${didDocMeta.toString()}');
      // print('didResMeta: ${didResMeta.toString()}');
    });
  });
}
