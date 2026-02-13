// ignore_for_file: avoid_print

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
          '@context': ['https://www.w3.org/ns/did/v1'],
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
          '@context': ['https://www.w3.org/ns/did/v1'],
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
          '@context': ['https://www.w3.org/ns/did/v1'],
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
          '@context': ['https://www.w3.org/ns/did/v1'],
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
          '@context': <String>['https://www.w3.org/ns/did/v1'],
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
          '@context': <String>['https://www.w3.org/ns/did/v1'],
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
          '@context': <String>['https://www.w3.org/ns/did/v1'],
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
          '@context': <String>['https://www.w3.org/ns/did/v1'],
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
          '@context': <String>['https://www.w3.org/ns/did/v1'],
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
          '@context': <String>['https://www.w3.org/ns/did/v1'],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Error parsing versionTime'),
        )),
      );
    });

    test('should throw SsiException when versionTime is missing timezone', () {
      final json = {
        'versionId': '1-QmHash',
        'versionTime': '2024-04-05T07:32:58',
        'parameters': <dynamic, dynamic>{},
        'state': {
          '@context': <String>['https://www.w3.org/ns/did/v1'],
          'id': 'did:webvh:scid:example.com',
        },
        'proof': <Map<String, dynamic>>[],
      };

      expect(
        () => DidWebVhLogEntry.fromJson(json),
        throwsA(isA<SsiException>().having(
          (e) => e.toString(),
          'message',
          contains('Error parsing versionTime'),
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
      expect(
          log.entries[0].versionTime, DateTime.parse('2024-04-05T07:32:58Z'));
      expect(
          log.entries[1].versionTime, DateTime.parse('2024-04-05T08:00:00Z'));
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

      expect(
          log.entries[0].versionTime, DateTime.parse('2024-01-01T00:00:00Z'));
      expect(
          log.entries[1].versionTime, DateTime.parse('2024-02-01T00:00:00Z'));
      expect(
          log.entries[2].versionTime, DateTime.parse('2024-03-01T00:00:00Z'));
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
      expect(
          log.entries[0].versionTime, DateTime.parse('2024-04-05T07:32:58Z'));
      expect(
          log.entries[1].versionTime, DateTime.parse('2024-04-05T08:00:00Z'));
    });
  });

  group('temp tests', () {
    test('temp test 1 - verify jsonlines from affinidi', () {
      final jsonLines = '''
{"versionId":"1-QmVPmCDEjUSaENdG1yxk9NgY7igSwqwHzk2cYNVxZr1QPr","versionTime":"2025-07-13T23:43:58Z","parameters":{"method":"did:webvh:1.0","scid":"Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai","updateKeys":["z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","z6MkuyEmpLCctNgEuz53V1tbLfLXdE3HBVjg1ReNwk3UDunz"],"portable":true,"nextKeyHashes":["QmZZmfw1J2Addwy5JSAobLEjvy5dVSNj1bxpfsaebseSwx","QmWZKGATFXYRPdmhpaJcGPBMo9S6iEaDzbBJN4w4wxvhmg","QmVYgnhRF6n9P2b5vw6E2sDBBVWhYHuQ8L37yDDDtMkr1S"],"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"},{"id":"did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"},{"id":"did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"},{"id":"did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"}]},"watchers":["https://watcher1.affinidi.com/"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:43:58Z","verificationMethod":"did:key:z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME#z6MkrA8fQayUTmk7E6dfY9N865vJcX5ZkQAKkDPGm1TXiXME","proofPurpose":"assertionMethod","proofValue":"z2A5qRuCf83hz2KPJJ7nydCgumfBujPjKbHemqWQMNmy6UWcshbx6sA5XB4RctvbCeLp1vFRKcbnxjs7k3iEEomsj"}]}
{"versionId":"2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj","versionTime":"2025-07-13T23:44:37Z","parameters":{"updateKeys":["z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7"],"nextKeyHashes":["QmfEfCsT5jfUc7YVHXXTTns3iB8PZyV9EZmuMRdeGxUmy8","QmXD1PK9KTmKz8roHfBkUFLS3h4Ha6NsrBVgdE8ARKWYyj","QmWNN2LiGANCwzBVf7r5ghB846wjCwSUtt6hsA16fSBLpW"],"ttl":60},"state":{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-13T23:44:37Z","verificationMethod":"did:key:z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7#z6MkwdX9kWL4qkZiQ1oG73WCKgWjcyCBX94EFF1PdeKoPEL7","proofPurpose":"assertionMethod","proofValue":"z3XG4m5mHcJLhdWCw9rxaGKf8u55rbhKfUDVkrQTQAyZ5NuC8fiKsrxh8BJ8fuQMQ3bkPkSuV2mYp2aYTc1WhxwyE"}]}
''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(
          log.entries[0].versionTime, DateTime.parse('2025-07-13T23:43:58Z'));
      expect(
          log.entries[1].versionTime, DateTime.parse('2025-07-13T23:44:37Z'));
      log.verify(null);
    });

    test('temp test 2 - verify jsonlines from python script', () {
      final jsonLines = '''
{"versionId": "1-QmQWAdDpS6vJJcVNciAd2tSZh6gR4cGYTmbxWtupq19Mi4", "versionTime": "2026-02-02T13:39:29Z", "parameters": {"updateKeys": ["z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV"], "method": "did:webvh:1.0", "scid": "QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:29Z", "proofPurpose": "assertionMethod", "proofValue": "z3fjSjWbV8eaFMvBFmtyaJUBgenNrqXCXF8S1nAtCXcUpT37ZGrhDTSNfEAJbNsLSJ561vxvxA9LNVhgMjZmotkH6"}]}
{"versionId": "2-Qmch9MxPayzKtkoUsQSi8ihgDGbFDvGZF2RYuGyfEq6fcE", "versionTime": "2026-02-02T13:39:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://identity.foundation/.well-known/did-configuration/v1"], "id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "authentication": ["did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"], "assertionMethod": ["did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"], "verificationMethod": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F", "controller": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkqswfEZyUVEhq16WFeTPYhyPCr5iBt7SbqyyUHjEZQd7F"}], "service": [{"id": "did:webvh:QmePoeHMWNAGxwjuJ1VjBV2aqtY997KA2T8CREReLocWu7:domain.example#domain", "type": "LinkedDomains", "serviceEndpoint": "https://domain.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV#z6MkpEndPpqQXExnJsQqHpc71Bq3L844c2BJGw9sA4bqGRaV", "created": "2026-02-02T13:39:30Z", "proofPurpose": "assertionMethod", "proofValue": "z53xk9p2Rub2eYs8jR65quHFJgH21HjPqJyRuKsQXEtyZKmXFzPsRSFS4otQXgcNTyjvv7F2YnN5Z6CuuM8J6RaXk"}]}''';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      expect(log.entries.length, equals(2));
      expect(
          log.entries[0].versionTime, DateTime.parse('2026-02-02T13:39:29Z'));
      expect(
          log.entries[1].versionTime, DateTime.parse('2026-02-02T13:39:30Z'));

      log.verify(null);
    });
  });
}
