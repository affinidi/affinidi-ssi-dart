import 'package:sdjwt_sdk/src/base/action.dart';

import '../base/hasher.dart';
import 'nonce_generator.dart';

/// Generates decoy digests for privacy protection in SD-JWT.
///
/// This class creates random digests that are indistinguishable from real disclosure digests,
/// enhancing privacy by making it difficult to determine which digests correspond to actual claims.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class DecoyDigestGenerator extends Action<int, Set<String>> {
  /// The [Hasher] used for creating decoy digests.
  final Hasher<String, String> hasher;

  /// Generator for secure random nonce values.
  final _nonceGenerator = Base64NonceGenerator();

  /// Creates a new decoy digest generator.
  ///
  /// Parameters:
  DecoyDigestGenerator(this.hasher);

  @override
  Set<String> execute(int input) {
    final Set<String> decoys = <String>{};
    for (int counter = 0; counter < input; counter++) {
      final decoy = hasher.execute(_nonceGenerator.generate());
      decoys.add(decoy);
    }
    return decoys;
  }
}
