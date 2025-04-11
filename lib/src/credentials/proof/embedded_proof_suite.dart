import '../../types.dart';
import 'embedded_proof.dart';

typedef DocumentLoader = Future<Map<String, dynamic>?> Function(Uri url);

class EmbeddedProofSuiteCreateOptions {
  final DocumentLoader customDocumentLoader;

  EmbeddedProofSuiteCreateOptions({this.customDocumentLoader = _noOpLoader});
}

class EmbeddedProofSuiteVerifyOptions {
  final DocumentLoader customDocumentLoader;

  EmbeddedProofSuiteVerifyOptions({this.customDocumentLoader = _noOpLoader});
}

abstract class EmbeddedProofSuite<
    CreateOptions extends EmbeddedProofSuiteCreateOptions,
    VerifyOptions extends EmbeddedProofSuiteVerifyOptions> {
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    CreateOptions options,
  );

  Future<VerificationResult> verifyProof(
    Map<String, dynamic> document,
    VerifyOptions options,
  );
}

Future<Map<String, dynamic>?> _noOpLoader(Uri url) async {
  return Future.value(null);
}
