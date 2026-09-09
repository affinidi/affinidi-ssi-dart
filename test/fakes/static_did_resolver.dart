import 'package:ssi/ssi.dart';

class StaticDidResolver implements DidResolver {
  StaticDidResolver(this.document);

  final DidDocument document;
  String? lastDid;

  @override
  Future<DidDocument> resolveDid(String did) async {
    lastDid = did;
    return document;
  }
}
