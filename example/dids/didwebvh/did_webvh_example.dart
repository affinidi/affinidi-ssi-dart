import 'package:ssi/src/did/did_webvh.dart';

Future<void> main() async {
  final did =
      'did:webvh:QmXi6hYqAUBKevKkUAbETFa6LKjvCSnuxdS1icQtiR4SAi:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:alice-with-witness';
  final parsedDid = DidWebVh.parse(did);
  print('Parsed DID: $parsedDid');
  final doc = await parsedDid.resolveDid();
  print('Resolved DID Document: $doc');
}
