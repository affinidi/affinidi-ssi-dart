import 'dart:convert';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

class TestDidResolver implements DidResolver {
  final Map<String, Map<String, dynamic>> _mockDocuments = {};

  void addMockDocument(String did, Map<String, dynamic> document) {
    _mockDocuments[did] = document;
  }

  @override
  Future<DidDocument> resolveDid(String did) async {
    final documentJson = _mockDocuments[did];
    if (documentJson == null) {
      throw SsiException(
        message: 'DID not found: $did',
        code: SsiExceptionType.unableToResolveDid.code,
      );
    }
    return DidDocument.fromJson(documentJson);
  }
}

void main() {
  group('DidResolver interface', () {
    test('custom implementation should resolve correctly', () async {
      final testResolver = TestDidResolver();
      final testDid = 'did:test:123';
      final mockDocument = jsonDecode(
        DidDocumentFixtures.didDocumentWithControllerKey,
      ) as Map<String, dynamic>;

      testResolver.addMockDocument(testDid, mockDocument);

      final resolvedDocument = await testResolver.resolveDid(testDid);
      expect(resolvedDocument.toJson(), equals(mockDocument));
    });

    test('custom implementation should handle missing DIDs', () async {
      final testResolver = TestDidResolver();
      const nonExistentDid = 'did:test:nonexistent';

      expect(
        () => testResolver.resolveDid(nonExistentDid),
        throwsA(
          isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.unableToResolveDid.code,
          ),
        ),
      );
    });

    test('custom implementation should resolve without resolver address',
        () async {
      final testResolver = TestDidResolver();
      final testDid = 'did:test:456';
      final mockDocument = jsonDecode(
        DidDocumentFixtures.didDocumentWithControllerKey,
      ) as Map<String, dynamic>;

      testResolver.addMockDocument(testDid, mockDocument);

      final resolvedDocument = await testResolver.resolveDid(testDid);
      expect(resolvedDocument.toJson(), equals(mockDocument));
    });

    test('interface contract should be enforced', () {
      final testResolver = TestDidResolver();
      expect(testResolver, isA<DidResolver>());

      final universalResolver = UniversalDIDResolver.defaultResolver;
      expect(universalResolver, isA<DidResolver>());
    });
  });
}
