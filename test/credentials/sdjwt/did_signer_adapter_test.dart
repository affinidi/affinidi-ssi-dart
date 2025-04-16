import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:sdjwt/sdjwt.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

// Expose a public version of the adapter for testing
class DidSignerAdapter implements Signer {
  final DidSigner _didSigner;

  DidSignerAdapter(this._didSigner);

  @override
  String get algIanaName => _didSigner.signatureScheme.jwtName != null
      ? _didSigner.signatureScheme.jwtName!
      : 'ES256K'; // Default to ES256K if no JWT name is available

  @override
  String? get keyId => _didSigner.keyId;

  @override
  Future<Uint8List> sign(Uint8List input) {
    return _didSigner.sign(input);
  }
}

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  late final DidSigner signer;
  late final DidSignerAdapter adapter;

  setUpAll(() async {
    signer = await initSigner(seed);
    adapter = DidSignerAdapter(signer);
  });

  group('DidSignerAdapter', () {
    test('should provide correct algorithm name from signature scheme', () {
      expect(adapter.algIanaName, equals('ES256K'));
    });

    test('should provide correct key id', () {
      expect(adapter.keyId, equals(signer.keyId));
    });

    test('should sign data using the underlying DidSigner syncSign method',
        () async {
      final testData = Uint8List.fromList([1, 2, 3, 4, 5]);

      final adapterSignature = await adapter.sign(testData);
      final directSignature = await signer.sign(testData);

      expect(adapterSignature, equals(directSignature));
    });

    test('should produce signatures that can be verified', () async {
      final testData = Uint8List.fromList([1, 2, 3, 4, 5]);

      final signature = await adapter.sign(testData);

      // Verify the signature matches what the adapter produces
      final directSignature = await signer.sign(testData);
      expect(signature, equals(directSignature));

      // Verify can be independently verified
      final wallet = Bip32Wallet.fromSeed(seed);
      final keyPair = await wallet.createKeyPair('0-0');

      final verified = await keyPair.verify(
        testData,
        signature,
        signatureScheme: signer.signatureScheme,
      );

      expect(verified, isTrue);
    });
  });
}
