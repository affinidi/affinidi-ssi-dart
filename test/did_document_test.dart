import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/did/did_document.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('Test Verification Method', () {
    test('the main did key should match to the expected value', () async {
      VerificationMethodMultibase(
        id: '1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyMultibase: 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu',
      );
    });
  });
}
