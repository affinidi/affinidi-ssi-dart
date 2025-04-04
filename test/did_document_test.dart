import 'dart:convert';

import 'package:ssi/src/did/did_document.dart';
import 'package:test/test.dart';

void main() {
  group('Test Verification Method', () {
    test('JWK conversion for Ed25519', () async {
      final vm = VerificationMethodMultibase(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyMultibase: 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu',
      );

      final expectedJson = jsonDecode(r'''
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "Zmq-CJA17UpFeVmJ-nIKDuDEhUnoRSNIXFbxyBtCh6Y"
        }
      ''');

      expect(vm.asJwk().toJson(), expectedJson);
    });

    test('multicodec conversion for Ed25519', () async {
      final vm = VerificationMethodJwk(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyJwk: Jwk.fromJson({
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "Zmq-CJA17UpFeVmJ-nIKDuDEhUnoRSNIXFbxyBtCh6Y"
        }),
      );

      final expectedMultibase =
          'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';
      expect(vm.asMultiBase(), expectedMultibase);
    });

    test('JWK conversion for secp256k1', () async {
      final vm = VerificationMethodMultibase(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyMultibase: 'zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj',
      );

      final expectedJson = jsonDecode(r'''
        {
          "kty": "EC",
          "crv": "secp256k1",
          "x": "8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg",
          "y": "4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8"
        }
      ''');

      expect(vm.asJwk().toJson(), expectedJson);
    });

    test('multicodec conversion for secp256k1', () async {
      final vm = VerificationMethodJwk(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyJwk: Jwk.fromJson({
          "kty": "EC",
          "crv": "secp256k1",
          "x": "8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg",
          "y": "4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8"
        }),
      );

      final expectedMultibase =
          'zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      expect(vm.asMultiBase(), expectedMultibase);
    });
  });
}
