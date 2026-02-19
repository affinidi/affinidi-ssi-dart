import 'package:ssi/src/did/did_webvh.dart';

Future<void> main() async {
  final did =
      'did:webvh:QmcwgCTuXndkHhsp6yA2s5MhTf5hP4VGZ6S3b6hzsTiiCK:mabdelsamei.com';
  final parsedDid = DidWebVh.parse(did);
  print('Parsed DID: $parsedDid');
  final doc = await parsedDid.resolveDid();
  print('Resolved DID Document: $doc');
}
