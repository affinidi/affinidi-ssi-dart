import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import 'did_manager.dart';

class DidWebManager extends DidManager {
  DidWebManager({required super.store, required super.wallet});

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) {
    // TODO: implement buildVerificationMethodId
    throw UnimplementedError();
  }

  @override
  Future<DidDocument> getDidDocument() {
    // TODO: implement getDidDocument
    throw UnimplementedError();
  }


}