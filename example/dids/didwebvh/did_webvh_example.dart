import 'package:ssi/src/did/did_webvh/did_webvh.dart';

Future<void> main() async {
  final did =
      'did:webvh:Qme2PYT44CZFzmT4ReHqGXAX4SVijyLCDJVELa6iBqXV1M:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness';
  final parsedDid = DidWebVhUrl.fromUrlString(did);
  print('Parsed DID: $parsedDid');
  final doc = await parsedDid.resolveDid();
  print('Resolved DID Document: $doc');
}
