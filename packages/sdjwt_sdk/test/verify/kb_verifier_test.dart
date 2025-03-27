import 'dart:convert';
import 'dart:io';

import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/models/sdjwt.dart';
import 'package:sdjwt_sdk/src/validator/kb_signer_input_validator.dart';
import 'package:sdjwt_sdk/src/verify/kb_verifier.dart';
import 'package:jose_plus/jose.dart';
import 'package:test/test.dart';

void main() {
  group('KbVerifier', () {
    late KbVerifyAction verifyAction;
    late SdJwtVerifyAction sdVerifier;
    late SDKeyVerifier verifier;
    late SdPublicKey issuerPublicKey;
    late JsonWebKey mockHolderKey;
    late SdJwt sdJwtWithoutCnf;
    late SdJwt sdJwtWithCnf;
    late Signer signer;
    late AsyncKbJwtSignerInputValidator validator;

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
      issuerPublicKey = SdPublicKey(publicKeyStr, SdJwtSignAlgorithm.rs256);

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

      sdVerifier = SdJwtVerifyAction();

      verifier = SDKeyVerifier(issuerPublicKey);

      validator = AsyncKbJwtSignerInputValidator();

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

    test('verify should throw for invalid JWT format', () async {
      expect(() => verifyAction.execute(sdJwtWithCnf.withKbJwt('invalid.jwt')),
          throwsArgumentError);
    });

    test('verify should throw for missing CNF claim', () async {
      expect(
          () => verifyAction.execute(sdJwtWithoutCnf.withKbJwt('invalid.jwt')),
          throwsException);
    });

    test('verify should throw for missing SD hash claim', () async {
      final jwt = createMockJwt({
        'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/
            1000,
        'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        'cnf': {'jwk': mockHolderKey.toJson()}
      });

      expect(() => verifyAction.execute(sdJwtWithCnf.withKbJwt(jwt)),
          throwsException);
    });

    test('verify should return false for invalid SD hash', () async {
      final jwt = createMockJwt({
        'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/
            1000,
        'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        'cnf': {'jwk': mockHolderKey.toJson()},
        'sd_hash': 'differentHash'
      });

      final result = verifyAction.execute(sdJwtWithCnf.withKbJwt(jwt));
      expect(result, isFalse);
    });

    test('verify should return false for expired token', () async {
      final jwt = createMockJwt({
        'exp': DateTime.now()
                .subtract(Duration(hours: 1))
                .millisecondsSinceEpoch ~/
            1000,
        'iat': DateTime.now()
                .subtract(Duration(hours: 2))
                .millisecondsSinceEpoch ~/
            1000,
        'cnf': {'jwk': mockHolderKey.toJson()},
        'sd_hash': 'mockHash'
      });

      final result = verifyAction.execute(sdJwtWithCnf.withKbJwt(jwt));
      expect(result, isFalse);
    });

    test('throws exception if SdJwt is not verified', () {
      final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
        sdJwt: sdJwtWithoutCnf,
        verifier: verifier,
        config: {},
      ));

      expect(verifiedSdJwt.isVerified, isFalse);

      final input = KbJwtSignerInput(
        sdJwtToken: sdJwtWithoutCnf,
        disclosuresToKeep: {},
        audience: 'https://example.com',
        holderPublicKey: null,
        signer: signer,
      );

      expect(
        () => validator.execute(input),
        throwsA(predicate((e) => e.toString().contains('must be verified'))),
      );
    });

    test('throws exception if disclosuresToKeep are not present in SD-JWT', () {
      final input = KbJwtSignerInput(
        sdJwtToken: sdJwtWithCnf,
        disclosuresToKeep: {
          Disclosure.from(
              salt: "dummy salt",
              claimValue: "dummy value",
              hasher: Base64EncodedOutputHasher.base64Sha256)
        },
        audience: 'https://example.com',
        holderPublicKey: null,
        signer: signer,
      );

      expect(
        () => validator.execute(input),
        throwsA(predicate(
            (e) => e.toString().contains('not all disclosuresToKeep'))),
      );
    });

    test('throws exception if cnf does not match holder key', () {
      final input = KbJwtSignerInput(
        sdJwtToken: sdJwtWithCnf,
        disclosuresToKeep: sdJwtWithCnf.disclosures,
        audience: 'https://example.com',
        holderPublicKey: SdPublicKey(
            File(
              'test/resources/ecdsa_sdjwt_test_private_key.pem',
            ).readAsStringSync(),
            SdJwtSignAlgorithm.es256),
        signer: signer,
      );

      expect(
        () => validator.execute(input),
        throwsA(predicate(
            (e) => e.toString().contains('`cnf` is invalid or missing'))),
      );
    });
  });
}
