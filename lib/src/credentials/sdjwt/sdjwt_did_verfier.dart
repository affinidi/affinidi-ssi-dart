import 'dart:typed_data';

import 'package:sdjwt/sdjwt.dart' show Verifier;
import 'package:ssi/ssi.dart' hide Verifier;

class SdJwtDidVerifier implements Verifier {
  final DidVerifier _delegate;

  SdJwtDidVerifier._(this._delegate);

  static Future<SdJwtDidVerifier> create({
    required SignatureScheme algorithm,
    required String kid,
    required String issuerDid,
    String? resolverAddress,
  }) async {
    final verifier = await DidVerifier.create(
      algorithm: algorithm,
      kid: kid,
      issuerDid: issuerDid,
      resolverAddress: resolverAddress,
    );

    return SdJwtDidVerifier._(verifier);
  }

  @override
  bool isAllowedAlgorithm(String algorithm) {
    return _delegate.isAllowedAlgorithm(algorithm);
  }

  @override
  bool verify(Uint8List data, Uint8List signature) {
    return _delegate.verify(data, signature);
  }
}
