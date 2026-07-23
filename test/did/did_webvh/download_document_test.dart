import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

/// An [http.Client] wrapper that records whether [close] was called and how
/// many requests were sent through it.
class _RecordingClient extends http.BaseClient {
  _RecordingClient(this._inner);

  final http.Client _inner;
  bool closed = false;
  int sendCount = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    sendCount++;
    return _inner.send(request);
  }

  @override
  void close() {
    closed = true;
    _inner.close();
  }
}

void main() {
  group('downloadDocument client ownership', () {
    final url = Uri.parse('https://example.com/.well-known/did.jsonl');

    test('does not close an externally provided client on success', () async {
      // The caller owns the client and may reuse its idle connections, so
      // downloadDocument must not close it.
      final client = _RecordingClient(
        MockClient((_) async => http.Response('document-body', 200)),
      );

      final body = await downloadDocument(url, client: client);

      expect(body, equals('document-body'));
      expect(client.sendCount, equals(1));
      expect(
        client.closed,
        isFalse,
        reason: 'an externally provided client must stay open for reuse',
      );
    });

    test('does not close an externally provided client on error', () async {
      final client = _RecordingClient(
        MockClient((_) async => http.Response('not found', 404)),
      );

      await expectLater(
        () => downloadDocument(url, client: client),
        throwsA(isA<SsiException>()),
      );

      expect(
        client.closed,
        isFalse,
        reason: 'an externally provided client must stay open even on error',
      );
    });
  });
}
