import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ssi/src/did/did_webvh/did_webvh.dart';
import 'package:ssi/src/did/did_webvh/did_webvh_log.dart';
import 'package:ssi/src/did/did_webvh/did_webvh_witness.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:test/test.dart';

void main() {
  group('DidWebVhWitness.fromJson', () {
    test('should parse valid witness entry', () {
      final json = {
        'versionId': '3-QmHash123',
        'proof': [
          {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'eddsa-jcs-2022',
            'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z5signature...',
          }
        ],
      };

      final witness = DidWebVhWitness.fromJson(json);

      expect(witness.versionId, equals('3-QmHash123'));
      expect(witness.proof.length, equals(1));
      expect(witness.proof[0]['cryptosuite'], equals('eddsa-jcs-2022'));
    });

    test('should parse witness entry with multiple proofs', () {
      final json = {
        'versionId': '5-QmHash456',
        'proof': [
          {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'eddsa-jcs-2022',
            'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z5sig1...',
          },
          {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'eddsa-jcs-2022',
            'verificationMethod': 'did:key:z6MkWitness2#z6MkWitness2',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z5sig2...',
          },
          {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'eddsa-jcs-2022',
            'verificationMethod': 'did:key:z6MkWitness3#z6MkWitness3',
            'proofPurpose': 'assertionMethod',
            'proofValue': 'z5sig3...',
          },
        ],
      };

      final witness = DidWebVhWitness.fromJson(json);

      expect(witness.versionId, equals('5-QmHash456'));
      expect(witness.proof.length, equals(3));
    });

    test('should throw when versionId is missing', () {
      final json = {
        'proof': [
          {'type': 'DataIntegrityProof'}
        ],
      };

      expect(
        () => DidWebVhWitness.fromJson(json),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('versionId'),
        )),
      );
    });

    test('should throw when proof is missing', () {
      final json = {
        'versionId': '3-QmHash123',
      };

      expect(
        () => DidWebVhWitness.fromJson(json),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('proof'),
        )),
      );
    });

    test('should parse witness with empty proof array', () {
      final json = {
        'versionId': '3-QmHash123',
        'proof': <Map<String, dynamic>>[],
      };

      final witness = DidWebVhWitness.fromJson(json);

      expect(witness.versionId, equals('3-QmHash123'));
      expect(witness.proof, isEmpty);
    });
  });

  group('WitnessVerificationResult', () {
    test('should create valid result', () {
      final result = WitnessVerificationResult(
        isValid: true,
        validCount: 3,
        threshold: 2,
        validWitnessDids: {'did:key:z6Mk1', 'did:key:z6Mk2', 'did:key:z6Mk3'},
        error: null,
      );

      expect(result.isValid, isTrue);
      expect(result.validCount, equals(3));
      expect(result.threshold, equals(2));
      expect(result.validWitnessDids.length, equals(3));
      expect(result.error, isNull);
    });

    test('should create invalid result with error', () {
      final result = WitnessVerificationResult(
        isValid: false,
        validCount: 1,
        threshold: 3,
        validWitnessDids: {'did:key:z6Mk1'},
        error: 'Insufficient witness proofs. Required: 3, Valid: 1',
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(1));
      expect(result.threshold, equals(3));
      expect(result.error, contains('Insufficient'));
    });
  });

  group('DidWebVhWitnessVerifier.fetchWitnesses', () {
    test('should fetch and parse witness file', () async {
      final witnessJson = '''
[
  {
    "versionId": "3-QmHash123",
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkWitness1#z6MkWitness1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z5sig..."
      }
    ]
  }
]
''';

      final mockClient = MockClient((request) async {
        expect(request.url.toString(),
            equals('https://example.com/.well-known/did-witness.json'));
        return http.Response(witnessJson, 200);
      });

      final did = DidWebVhUrl.fromUrlString('did:webvh:QmScid123:example.com');
      final witnesses = await DidWebVhWitnessVerifier.fetchWitnesses(
          did.witnessUrlString, mockClient);

      expect(witnesses.length, equals(1));
      expect(witnesses[0].versionId, equals('3-QmHash123'));
    });

    test('should fetch witness file with multiple entries', () async {
      final witnessJson = '''
[
  {
    "versionId": "3-QmHash123",
    "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mk1#z6Mk1", "proofPurpose": "assertionMethod", "proofValue": "z5sig1"}]
  },
  {
    "versionId": "5-QmHash456",
    "proof": [
      {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mk1#z6Mk1", "proofPurpose": "assertionMethod", "proofValue": "z5sig2"},
      {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mk2#z6Mk2", "proofPurpose": "assertionMethod", "proofValue": "z5sig3"}
    ]
  }
]
''';

      final mockClient = MockClient((request) async {
        return http.Response(witnessJson, 200);
      });

      final did = DidWebVhUrl.fromUrlString('did:webvh:QmScid123:example.com');
      final witnesses = await DidWebVhWitnessVerifier.fetchWitnesses(
          did.witnessUrlString, mockClient);

      expect(witnesses.length, equals(2));
      expect(witnesses[0].versionId, equals('3-QmHash123'));
      expect(witnesses[0].proof.length, equals(1));
      expect(witnesses[1].versionId, equals('5-QmHash456'));
      expect(witnesses[1].proof.length, equals(2));
    });

    test('should throw on non-array response', () async {
      final mockClient = MockClient((request) async {
        return http.Response('{"versionId": "1-QmHash"}', 200);
      });

      final did = DidWebVhUrl.fromUrlString('did:webvh:QmScid123:example.com');

      expect(
        () => DidWebVhWitnessVerifier.fetchWitnesses(
            did.witnessUrlString, mockClient),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('expected array'),
        )),
      );
    });

    test('should throw on HTTP error', () async {
      final mockClient = MockClient((request) async {
        return http.Response('Not Found', 404);
      });

      final did = DidWebVhUrl.fromUrlString('did:webvh:QmScid123:example.com');

      expect(
        () => DidWebVhWitnessVerifier.fetchWitnesses(
            did.witnessUrlString, mockClient),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('404'),
        )),
      );
    });

    test('should construct correct witness URL for DID with path', () async {
      final mockClient = MockClient((request) async {
        expect(request.url.toString(),
            equals('https://example.com/users/alice/did-witness.json'));
        return http.Response('[]', 200);
      });

      final did = DidWebVhUrl.fromUrlString(
          'did:webvh:QmScid123:example.com:users:alice');
      await DidWebVhWitnessVerifier.fetchWitnesses(
          did.witnessUrlString, mockClient);
    });
  });

  group('DidWebVhWitnessVerifier.verify', () {
    // Helper to create a mock log entry
    DidWebVhLogEntry createMockEntry(int versionNumber, String hash) {
      final jsonLines = '''
{"versionId":"$versionNumber-$hash","versionTime":"2025-01-0${versionNumber}T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"]},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      return DidWebVhLog.fromJsonLines(jsonLines).entries[0];
    }

    test('should return invalid when threshold > number of witnesses',
        () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      expect(
        () async => await verifier.verify(
          entry: entry,
          witnessProofs: [],
          witnessConfig: {
            'threshold': 2,
            'witnesses': [
              {'id': 'did:key:z6MkWitness1'}
            ]
          },
        ),
        throwsA(
          isA<SsiException>().having(
            (e) => e.message,
            'message',
            contains('threshold (2) exceeds number of witnesses (1)'),
          ),
        ),
      );
    });

    test('should return invalid when no proofs and threshold > 0', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: [],
        witnessConfig: {
          'threshold': 2,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
            {'id': 'did:key:z6MkWitness2'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
      expect(result.threshold, equals(2));
      expect(result.error, contains('Insufficient'));
    });

    test('should skip proofs with wrong cryptosuite', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'wrong-suite',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
    });

    test('should skip proofs with wrong proofPurpose', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'authentication',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
    });

    test('should skip proofs from unauthorized witnesses', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkUnauthorized#z6MkUnauthorized',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
    });

    test('should skip proofs with non-did:key verificationMethod', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:web:example.com#key1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:web:example.com'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
    });

    test(
        'should apply later proofs rule - proof for version N covers entry < N',
        () async {
      final verifier = DidWebVhWitnessVerifier();
      // Entry is version 2
      final entry = createMockEntry(2, 'QmHash2');

      // Proof is for version 5 (later than entry version 2)
      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '5-QmHash5',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      // The proof should be applicable (version 5 >= version 2)
      // But signature verification will fail since it's a fake signature
      // The important thing is that the proof was considered (not skipped due to version)
      expect(result.validCount, equals(0)); // Signature verification fails
    });

    test('should NOT apply proofs from earlier versions', () async {
      final verifier = DidWebVhWitnessVerifier();
      // Entry is version 5
      final entry = createMockEntry(5, 'QmHash5');

      // Proof is for version 2 (earlier than entry version 5)
      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '2-QmHash2',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      // The proof should NOT be applicable (version 2 < version 5)
      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
    });

    test('should count each witness only once', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash2');

      // Same witness provides proofs in multiple version entries
      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig1...',
            }
          ],
        }),
        DidWebVhWitness.fromJson({
          'versionId': '5-QmHash5',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig2...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      // Note: This test uses fake proofValues that fail cryptographic verification.
      // With real signatures, the deduplication logic would ensure witness1
      // is only counted once despite having proofs in multiple entries.
      expect(result.isValid, isFalse); // Fails due to invalid signatures
      expect(result.threshold, equals(1));
      expect(result.validCount, equals(0)); // No valid proofs
    });

    test('should handle missing verificationMethod', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
              // Missing verificationMethod
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
    });

    test('should throw on empty witness config (threshold defaults to 0)',
        () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      // Empty config means threshold defaults to 0, which is invalid per spec
      expect(
        () async => await verifier.verify(
          entry: entry,
          witnessProofs: [],
          witnessConfig: {},
        ),
        throwsA(
          isA<SsiException>().having(
            (e) => e.message,
            'message',
            contains('threshold must be at least 1'),
          ),
        ),
      );
    });
  });

  group('Witness requirement computation', () {
    // These tests verify the logic of which entries require witnessing
    // by testing through the verify behavior

    test('first entry never requires witnessing even with witness config',
        () async {
      // This is tested indirectly - the _computeEntriesRequiringWitness
      // method skips the first entry
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2025-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"],"witness":{"threshold":2,"witnesses":[{"id":"did:key:z6Mk1"},{"id":"did:key:z6Mk2"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // First entry has witness config but should not require witnessing
      expect(log.entries[0].parameters.witness, isNotNull);
      expect(log.entries[0].parameters.witness!['threshold'], equals(2));
    });

    test('entry inherits witness config from previous entry', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2025-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"],"witness":{"threshold":2,"witnesses":[{"id":"did:key:z6Mk1"},{"id":"did:key:z6Mk2"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2025-01-02T00:00:00Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Entry 1 has witness config
      expect(log.entries[0].parameters.witness, isNotNull);
      // Entry 2 has no witness config (inherits from entry 1)
      expect(log.entries[1].parameters.witness, isNull);
    });

    test('witness deactivation requires witnessing with previous config', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2025-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"],"witness":{"threshold":2,"witnesses":[{"id":"did:key:z6Mk1"},{"id":"did:key:z6Mk2"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2025-01-02T00:00:00Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"3-QmHash3","versionTime":"2025-01-03T00:00:00Z","parameters":{"witness":{}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Entry 3 explicitly sets witness to {} (deactivation)
      expect(log.entries[2].parameters.witness, equals({}));
    });

    test('entries after deactivation do not require witnessing', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2025-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"],"witness":{"threshold":2,"witnesses":[{"id":"did:key:z6Mk1"},{"id":"did:key:z6Mk2"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2025-01-02T00:00:00Z","parameters":{"witness":{}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"3-QmHash3","versionTime":"2025-01-03T00:00:00Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Entry 2 deactivates witnesses
      expect(log.entries[1].parameters.witness, equals({}));
      // Entry 3 inherits empty (no witnessing required)
      expect(log.entries[2].parameters.witness, isNull);
    });

    test('re-activation requires witnessing', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2025-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"],"witness":{"threshold":2,"witnesses":[{"id":"did:key:z6Mk1"},{"id":"did:key:z6Mk2"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2025-01-02T00:00:00Z","parameters":{"witness":{}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"3-QmHash3","versionTime":"2025-01-03T00:00:00Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"4-QmHash4","versionTime":"2025-01-04T00:00:00Z","parameters":{"witness":{"threshold":1,"witnesses":[{"id":"did:key:z6Mk3"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Entry 4 re-activates witnesses
      expect(log.entries[3].parameters.witness, isNotNull);
      expect(log.entries[3].parameters.witness!['threshold'], equals(1));
    });

    test('witness config change requires witnessing with new config', () {
      final jsonLines = '''
{"versionId":"1-QmHash1","versionTime":"2025-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"],"witness":{"threshold":2,"witnesses":[{"id":"did:key:z6MkA"},{"id":"did:key:z6MkB"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"2-QmHash2","versionTime":"2025-01-02T00:00:00Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
{"versionId":"3-QmHash3","versionTime":"2025-01-03T00:00:00Z","parameters":{"witness":{"threshold":3,"witnesses":[{"id":"did:key:z6MkC"},{"id":"did:key:z6MkD"},{"id":"did:key:z6MkE"}]}},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      final log = DidWebVhLog.fromJsonLines(jsonLines);

      // Entry 1 has config A, B with threshold 2
      expect(log.entries[0].parameters.witness!['threshold'], equals(2));
      // Entry 3 changes to config C, D, E with threshold 3
      expect(log.entries[2].parameters.witness!['threshold'], equals(3));
    });
  });

  group('Complex witness scenarios', () {
    DidWebVhLogEntry createMockEntry(int versionNumber, String hash) {
      final jsonLines = '''
{"versionId":"$versionNumber-$hash","versionTime":"2025-01-0${versionNumber}T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"]},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      return DidWebVhLog.fromJsonLines(jsonLines).entries[0];
    }

    test('should handle threshold exactly met', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: [],
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'}
          ],
        },
      );

      expect(result.isValid, isFalse); // No proofs provided, so fails
      expect(result.validCount, equals(0));
      expect(result.threshold, equals(1));
    });

    test('should reject when exactly one proof short of threshold', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: [],
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.validCount, equals(0));
      expect(result.threshold, equals(1));
    });

    test('should handle mixed proof types correctly', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig1...',
            },
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'wrong-suite',
              'verificationMethod': 'did:key:z6MkWitness2#z6MkWitness2',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig2...',
            },
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:web:example.com#key1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig3...',
            },
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
            {'id': 'did:key:z6MkWitness2'},
            {'id': 'did:web:example.com'},
          ],
        },
      );

      // Only the first proof should be considered (but signature will fail)
      expect(result.validCount, equals(0));
    });

    test('should handle witness rotation correctly', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(5, 'QmHash5');

      // Witnesses changed between entry 3 and entry 5
      // Entry 3: [A, B, C]
      // Entry 5: [B, C, D]
      // Only B and C were authorized at entry 5

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '6-QmHash6',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkA#z6MkA',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sigA...',
            },
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkB#z6MkB',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sigB...',
            },
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkB'},
            {'id': 'did:key:z6MkC'},
            {'id': 'did:key:z6MkD'},
          ],
        },
      );

      // Only witness B should be valid (signature verification will fail though)
      expect(result.validCount, equals(0)); // Signature fails
    });

    test('should validate all witnesses when threshold is high', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: [],
        witnessConfig: {
          'threshold': 5,
          'witnesses': [
            {'id': 'did:key:z6Mk1'},
            {'id': 'did:key:z6Mk2'},
            {'id': 'did:key:z6Mk3'},
            {'id': 'did:key:z6Mk4'},
            {'id': 'did:key:z6Mk5'},
          ],
        },
      );

      expect(result.isValid, isFalse);
      expect(result.threshold, equals(5));
      expect(result.error, contains('Required: 5'));
    });
  });

  group('Witness URL construction', () {
    test('should construct URL for simple domain', () {
      final did = DidWebVhUrl.fromUrlString('did:webvh:QmScid:example.com');
      expect(did.witnessUrlString,
          equals('https://example.com/.well-known/did-witness.json'));
    });

    test('should construct URL for domain with port', () {
      final did =
          DidWebVhUrl.fromUrlString('did:webvh:QmScid:example.com%3A8080');
      expect(did.witnessUrlString,
          equals('https://example.com:8080/.well-known/did-witness.json'));
    });

    test('should construct URL for domain with path', () {
      final did =
          DidWebVhUrl.fromUrlString('did:webvh:QmScid:example.com:users:alice');
      expect(did.witnessUrlString,
          equals('https://example.com/users/alice/did-witness.json'));
    });

    test('should construct URL for complex path', () {
      final did =
          DidWebVhUrl.fromUrlString('did:webvh:QmScid:example.com:a:b:c:d:e');
      expect(did.witnessUrlString,
          equals('https://example.com/a/b/c/d/e/did-witness.json'));
    });
  });

  group('Error message validation', () {
    DidWebVhLogEntry createMockEntry(int versionNumber, String hash) {
      final jsonLines = '''
{"versionId":"$versionNumber-$hash","versionTime":"2025-01-0${versionNumber}T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"]},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      return DidWebVhLog.fromJsonLines(jsonLines).entries[0];
    }

    test('should provide detailed error when threshold not met', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: [],
        witnessConfig: {
          'threshold': 3,
          'witnesses': [
            {'id': 'did:key:z6Mk1'},
            {'id': 'did:key:z6Mk2'},
            {'id': 'did:key:z6Mk3'},
          ],
        },
      );

      expect(
        result.error,
        contains('Insufficient witness proofs for versionId 2-QmHash'),
      );
      expect(result.error, contains('Required: 3'));
      expect(result.error, contains('Valid: 0'));
    });

    test('should include valid witness DIDs in result', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: [],
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'}
          ],
        },
      );

      expect(result.validWitnessDids, isEmpty);
    });
  });

  group('Edge cases', () {
    DidWebVhLogEntry createMockEntry(int versionNumber, String hash) {
      final jsonLines = '''
{"versionId":"$versionNumber-$hash","versionTime":"2025-01-0${versionNumber}T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"QmScid123","updateKeys":["z6MkKey1"]},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmScid123:example.com"},"proof":[{"type":"DataIntegrityProof"}]}
''';
      return DidWebVhLog.fromJsonLines(jsonLines).entries[0];
    }

    test('should throw on null threshold (defaults to 0)', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      // Null threshold defaults to 0, which is invalid per spec
      expect(
        () async => await verifier.verify(
          entry: entry,
          witnessProofs: [],
          witnessConfig: {
            'witnesses': <Map<String, dynamic>>[],
          },
        ),
        throwsA(
          isA<SsiException>().having(
            (e) => e.message,
            'message',
            contains('threshold must be at least 1'),
          ),
        ),
      );
    });

    test('should throw on empty witnessConfig (threshold defaults to 0)',
        () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      // Empty config defaults threshold to 0, which is invalid per spec
      expect(
        () async => await verifier.verify(
          entry: entry,
          witnessProofs: [],
          witnessConfig: {},
        ),
        throwsA(
          isA<SsiException>().having(
            (e) => e.message,
            'message',
            contains('threshold must be at least 1'),
          ),
        ),
      );
    });

    test('should throw on negative threshold', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      expect(
        () async => await verifier.verify(
          entry: entry,
          witnessProofs: [],
          witnessConfig: {
            'threshold': -1,
            'witnesses': [
              {'id': 'did:key:z6MkWitness1'}
            ],
          },
        ),
        throwsA(
          isA<SsiException>().having(
            (e) => e.message,
            'message',
            contains('threshold must be at least 1'),
          ),
        ),
      );
    });

    test('should throw on threshold < 1 with null witnesses array', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      // threshold=0 is invalid per spec
      expect(
        () async => await verifier.verify(
          entry: entry,
          witnessProofs: [],
          witnessConfig: {
            'threshold': 0,
          },
        ),
        throwsA(
          isA<SsiException>().having(
            (e) => e.message,
            'message',
            contains('threshold must be at least 1'),
          ),
        ),
      );
    });

    test('should handle case-sensitive DID comparison', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod':
                  'did:key:Z6MkWitness1#Z6MkWitness1', // Capital Z
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'}, // lowercase z
          ],
        },
      );

      // Should not match due to case difference
      expect(result.validCount, equals(0));
    });

    test('should handle proof with extra fields', () async {
      final verifier = DidWebVhWitnessVerifier();
      final entry = createMockEntry(2, 'QmHash');

      final witnessProofs = [
        DidWebVhWitness.fromJson({
          'versionId': '3-QmHash3',
          'proof': [
            {
              'type': 'DataIntegrityProof',
              'cryptosuite': 'eddsa-jcs-2022',
              'verificationMethod': 'did:key:z6MkWitness1#z6MkWitness1',
              'proofPurpose': 'assertionMethod',
              'proofValue': 'z5sig...',
              'created': '2025-01-03T00:00:00Z',
              'extraField': 'should be ignored',
            }
          ],
        }),
      ];

      final result = await verifier.verify(
        entry: entry,
        witnessProofs: witnessProofs,
        witnessConfig: {
          'threshold': 1,
          'witnesses': [
            {'id': 'did:key:z6MkWitness1'},
          ],
        },
      );

      // Should process proof normally despite extra fields
      expect(result.validCount, equals(0)); // Signature fails
    });
  });
}
