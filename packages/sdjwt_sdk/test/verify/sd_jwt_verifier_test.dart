import 'dart:io';

import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/models/sdjwt.dart';
import 'package:test/test.dart';

void main() {
  group('SdJwtVerifier Tests', () {
    late SdPrivateKey issuerPrivateKey;
    late SdPublicKey issuerPublicKey;
    late SdJwtVerifyAction sdVerifier;
    late SdJwtSigner sdSigner;
    late SDKeySigner signer;
    late SDKeyVerifier verifier;

    final emptyConfig = <String, dynamic>{};
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

    // Decode header and payload with proper base64 padding
    setUp(() {
      final privateKeyFile = File(
        'test/resources/rsa_sdjwt_test_private_key.pem',
      );
      final publicKeyFile = File(
        'test/resources/rsa_sdjwt_test_public_key.pem',
      );

      final privateKeyStr = privateKeyFile.readAsStringSync();
      final publicKeyStr = publicKeyFile.readAsStringSync();

      issuerPrivateKey = SdPrivateKey(privateKeyStr, SdJwtSignAlgorithm.rs256);
      issuerPublicKey = SdPublicKey(publicKeyStr, SdJwtSignAlgorithm.rs256);

      signer = SDKeySigner(issuerPrivateKey);
      verifier = SDKeyVerifier(issuerPublicKey);

      sdVerifier = SdJwtVerifyAction();
      sdSigner = SdJwtSigner();
    });

    group('Disclosures  Tests', () {
      test(
          'it should successfully verify and resolve disclosures for valid sdjwt',
          () async {
        final SdJwtSignerInput signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(claims),
          disclosureFrame: disclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
        );

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['first_name'], equals('Rain'));
        expect(result['last_name'], equals('Bow'));
        expect(result.containsKey('_sd_alg'), isFalse);
      });

      test('should handle flat disclosures correctly', () async {
        final flatClaims = {
          'id': '1234',
          'name': 'Rain',
          'age': 25,
          'city': 'Berlin',
        };
        final flatDisclosureFrame = {
          '_sd': ['age', 'city'],
        };

        final signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(flatClaims),
          disclosureFrame: flatDisclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
        );

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['name'], equals('Rain'));
        expect(result['age'], equals(25));
        expect(result['city'], equals('Berlin'));
        expect(result.containsKey('_sd_alg'), isFalse);
      });

      test('should verify SD-JWT with different hashing algorithms', () async {
        final bundledBase64Hashers = List.unmodifiable([
          Base64EncodedOutputHasher.base64Sha256,
          Base64EncodedOutputHasher.base64Sha384,
          Base64EncodedOutputHasher.base64Sha512,
          Base64EncodedOutputHasher.base64Sha512_256
        ]);

        for (final hasher in bundledBase64Hashers) {
          final claimsWithAlg = Map<String, dynamic>.from(claims);

          final signerInput = SdJwtSignerInput(
            claims: claimsWithAlg,
            disclosureFrame: disclosureFrame,
            signer: signer,
            hasher: hasher,
          );

          final sdjwt = sdSigner.execute(signerInput);
          final serialized = '${[
            sdjwt.jwsString,
            ...sdjwt.disclosures.map((e) => e.serialized)
          ].join(disclosureSeparator)}~';

          final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
            sdJwt: SdJwt.parse(serialized),
            verifier: verifier,
            config: emptyConfig,
          ));

          final result = verifiedSdJwt.claims;
          expect(result['id'], equals('1234'));
          expect(result['first_name'], equals('Rain'));
          expect(result['last_name'], equals('Bow'));
          expect(result.containsKey('_sd_alg'), isFalse);
        }
      });
    });

    group('KB Tests', () {
      test('should verify successfully with valid kb', () async {
        final holderKeyFile = File(
          'test/resources/rsa_sdjwt_test_public_key.pem',
        );
        final String holderKeyStr = holderKeyFile.readAsStringSync();
        final SdPublicKey holderSdKey =
            SdPublicKey(holderKeyStr, SdJwtSignAlgorithm.rs256);

        final signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(claims),
          disclosureFrame: disclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
          holderPublicKey: holderSdKey,
        );

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['first_name'], equals('Rain'));
        expect(result['last_name'], equals('Bow'));
        expect(result.containsKey('_sd_alg'), isFalse);
        expect(result.containsKey('cnf'), isTrue);
      });

      test(
          'should return claims when kb is required but holder key is missing.',
          () async {
        final holderKeyFile = File(
          'test/resources/rsa_sdjwt_test_public_key.pem',
        );
        final holderKeyStr = holderKeyFile.readAsStringSync();
        final holderSdKey = SdPublicKey(holderKeyStr, SdJwtSignAlgorithm.rs256);

        final signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(claims),
          disclosureFrame: disclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
          holderPublicKey: holderSdKey,
        );
        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['first_name'], equals('Rain'));
        expect(result['last_name'], equals('Bow'));
        expect(result.containsKey('_sd_alg'), isFalse);
        expect(result.containsKey('cnf'), isTrue);
      });

      test('should handle multiple _sd_alg occurrences', () async {
        final invalidClaims = {
          '_sd_alg': 'sha-256',
          'extra': {'_sd_alg': 'sha-256', 'value': 'test'}
        };

        final signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(invalidClaims),
          disclosureFrame: {
            'extra': {'value': true}
          },
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
        );

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        expect(verifiedSdJwt.claims['extra']['value'], equals('test'));
      });

      test('should process claims when _sd_alg is missing at top level',
          () async {
        final claimsWithoutSdAlg = Map<String, dynamic>.from(claims);

        final signerInput = SdJwtSignerInput(
          claims: claimsWithoutSdAlg,
          disclosureFrame: disclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
        );

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['first_name'], equals('Rain'));
        expect(result['last_name'], equals('Bow'));
        expect(result.containsKey('_sd_alg'), isFalse);
      });
    });

    group('ES256K Tests', () {
      test('should verify ES256K signed SD-JWT successfully', () async {
        final SdJwtSignerInput signerInput = SdJwtSignerInput(
            claims: Map<String, dynamic>.from(claims),
            disclosureFrame: disclosureFrame,
            signer: signer,
            hasher: Base64EncodedOutputHasher.base64Sha256);

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['first_name'], equals('Rain'));
        expect(result['last_name'], equals('Bow'));
        expect(result.containsKey('_sd_alg'), isFalse);
      });

      test('should verify ES256K signed SD-JWT with key binding', () async {
        final holderKeyFile = File(
          'test/resources/secp256k1_sdjwt_test_public_key.pem',
        );
        final String holderKeyStr = holderKeyFile.readAsStringSync();
        final SdPublicKey holderSdKey =
            SdPublicKey(holderKeyStr, SdJwtSignAlgorithm.es256k);

        final signerInput = SdJwtSignerInput(
          claims: Map<String, dynamic>.from(claims),
          disclosureFrame: disclosureFrame,
          signer: signer,
          hasher: Base64EncodedOutputHasher.base64Sha256,
          holderPublicKey: holderSdKey,
        );

        final sdjwt = sdSigner.execute(signerInput);
        final serialized = '${[
          sdjwt.jwsString,
          ...sdjwt.disclosures.map((e) => e.serialized)
        ].join(disclosureSeparator)}~';

        final verifiedSdJwt = sdVerifier.execute(SdJwtVerifierInput(
          sdJwt: SdJwt.parse(serialized),
          verifier: verifier,
          config: emptyConfig,
        ));

        final result = verifiedSdJwt.claims;
        expect(result['id'], equals('1234'));
        expect(result['first_name'], equals('Rain'));
        expect(result['last_name'], equals('Bow'));
        expect(result.containsKey('_sd_alg'), isFalse);
        expect(result.containsKey('cnf'), isTrue);
      });
    });
  });
}
