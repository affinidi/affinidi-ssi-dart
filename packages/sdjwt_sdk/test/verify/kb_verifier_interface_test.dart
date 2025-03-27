import 'dart:convert';
import 'dart:io';

import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/models/sdjwt.dart';
import 'package:sdjwt_sdk/src/verify/kb_verifier.dart';
import 'package:jose_plus/jose.dart';
import 'package:test/test.dart';

void main() {
  group('KBVerifierInterface', () {
    late KbVerifyAction verifyAction;
    late JsonWebKey mockHolderKey;
    late SdJwt sdJwtWithoutCnf;
    late SdJwt sdJwtWithCnf;
    late Signer signer;

    final claims = {
      'id': '1234',
      'first_name': 'Rain',
      'last_name': 'Bow',
    };
    final disclosureFrame = {
      '_sd': [
        'last_name',
      ],
    };

    setUp(() async {
      final privateKeyFile = File(
        'test/resources/ecdsa_sdjwt_test_private_key.pem',
      );
      final publicKeyFile = File(
        'test/resources/ecdsa_sdjwt_test_public_key.pem',
      );

      final privateKeyStr = privateKeyFile.readAsStringSync();
      final publicKeyStr = publicKeyFile.readAsStringSync();

      final issuerPrivateKey =
          SdPrivateKey(privateKeyStr, SdJwtSignAlgorithm.es256);
      final holderPublicKey =
          SdPublicKey(publicKeyStr, SdJwtSignAlgorithm.es256);

      signer = SDKeySigner(issuerPrivateKey);

      final sdSigner = SdJwtSigner();

      final SdJwtSignerInput signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(claims),
          disclosureFrame: disclosureFrame,
          hasher: Base64EncodedOutputHasher.base64Sha256,
          signer: signer);

      sdJwtWithoutCnf = sdSigner.execute(signerInput);

      final SdJwtSignerInput signerInputWithCnf = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(claims),
          disclosureFrame: disclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
          holderPublicKey: holderPublicKey);
      sdJwtWithCnf = sdSigner.execute(signerInputWithCnf);

      verifyAction = KbVerifyAction();

      mockHolderKey = JsonWebKey.fromJson({
        'kty': 'EC',
        'crv': 'P-256',
        'x': base64Url.encode(List.filled(32, 1)),
        'y': base64Url.encode(List.filled(32, 2))
      })!;
    });

    String createMockJwt(Map<String, dynamic> payload) {
      final jwtSigner = SdJwtSigner();
      return jwtSigner.generateSignedCompactJwt(
          signer: signer, claims: payload, protectedHeaders: {'typ': 'jwt'});
    }

    test('verify should delegate to verifyAction', () async {
      final jwt = createMockJwt({
        'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/
            1000,
        'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        'cnf': {'jwk': mockHolderKey.toJson()},
        'sd_hash': 'differentHash'
      });

      final result = verifyAction.execute(sdJwtWithCnf.withKbJwt(jwt));

      expect(result, isA<bool>());
      expect(result, isFalse);
    });

    test('verify should throw for empty token', () async {
      expect(() {
        verifyAction.execute(sdJwtWithCnf.withKbJwt(''));
      }, throwsException);
    });

    test('verify should throw for malformed token', () async {
      expect(() async {
        verifyAction.execute(sdJwtWithoutCnf.withKbJwt('invalid.jwt'));
      }, throwsException);
    });
  });
}
