import 'package:ssi/src/did/did_webvh/did_webvh.dart';
import 'dart:convert';
import 'package:crypto/crypto.dart';

Future<void> main() async {
  final did =
      'did:webvh:Qme2PYT44CZFzmT4ReHqGXAX4SVijyLCDJVELa6iBqXV1M:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness';
  final parsedDid = DidWebVhUrl.fromUrlString(did);
  final (doc, docMeta, resMeta) = await parsedDid.resolveDid();
  print('Resolved DID Document: $doc');
  try {
    final jsonDoc = jsonEncode(doc.toJson());
    final bytes = utf8.encode(jsonDoc);
    final hash = sha256.convert(bytes).toString();
    print('DID Document SHA-256: $hash');
  } catch (e) {
    print('Failed to hash DID Document: $e');
  }
}
