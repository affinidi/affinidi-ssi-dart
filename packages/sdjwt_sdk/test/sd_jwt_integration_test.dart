import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('SdJwt Integration', () {
    String addBase64Padding(String str) {
      if (str.isEmpty) return str;
      final padLength = 4 - (str.length % 4);
      return padLength == 4 ? str : str + ('=' * padLength);
    }

    final resourcesPath =
        path.join(Directory.current.path, 'test', 'resources');
    late SdPrivateKey issuerPrivateKey;
    late SDKeySigner signer;

    setUp(() {
      final issuerPrivateKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_private_key.pem',
      ));

      if (!issuerPrivateKeyFile.existsSync()) {
        throw FileSystemException(
          'Key files not found. Please run from project root.',
          issuerPrivateKeyFile.path,
        );
      }

      issuerPrivateKey = SdPrivateKey(
        issuerPrivateKeyFile.readAsStringSync(),
        SdJwtSignAlgorithm.es256k,
      );
      signer = SDKeySigner(issuerPrivateKey);
    });

    test('Generate SD-JWT without Key Binding', () async {
      final claims = {
        'given_name': 'Harry',
        'family_name': 'Potter',
        'email': 'harry.p@example.com',
        'address': {
          'street': '123 Main St',
          'city': 'Berlin',
          'country': 'DE',
        },
        'birth_date': '1990-01-01'
      };

      final selectiveDisclosureClaims = {
        '_sd': [
          'given_name',
          'email',
          'birth_date',
        ]
      };

      final handler = SdJwtHandlerV1();

      final sdJwt = handler.sign(
        claims: claims,
        disclosureFrame: selectiveDisclosureClaims,
        signer: signer,
      );

      expect(sdJwt.serialized, isNotEmpty);

      final parts = sdJwt.serialized.split('~');
      expect(parts.length > 1, isTrue);

      final jwtSegments = parts.first.split('.');
      expect(jwtSegments.length, equals(3));

      final headerJson = jsonDecode(
          utf8.decode(base64Url.decode(addBase64Padding(jwtSegments[0]))));
      expect(headerJson['typ'], equals('sd+jwt'));
      expect(headerJson['alg'], equals(SdJwtSignAlgorithm.es256k.ianaName));

      final payloadJson = jsonDecode(
          utf8.decode(base64Url.decode(addBase64Padding(jwtSegments[1]))));
      expect(payloadJson['family_name'], equals('Potter'));
      expect(payloadJson['_sd'], isA<List>());
      expect(payloadJson['_sd_alg'], equals('sha-256'));
      expect(payloadJson.containsKey('given_name'), isFalse);
      expect(payloadJson.containsKey('email'), isFalse);
      expect(payloadJson.containsKey('birth_date'), isFalse);

      final disclosures =
          parts.skip(1).where((part) => part.isNotEmpty).toList();
      expect(disclosures.length, equals(3)); // should have 3 disclosures

      final publicKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_public_key.pem',
      ));

      final publicKey = SdPublicKey(
        publicKeyFile.readAsStringSync(),
        SdJwtSignAlgorithm.es256k,
      );

      final verifier = SDKeyVerifier(publicKey);

      final verifiedSdJwt = handler.verify(
        sdJwt: sdJwt,
        verifier: verifier,
      );

      expect(verifiedSdJwt.claims['given_name'], equals('Harry'));
      expect(verifiedSdJwt.claims['family_name'], equals('Potter'));
      expect(verifiedSdJwt.claims['email'], equals('harry.p@example.com'));
      expect(verifiedSdJwt.claims['birth_date'], equals('1990-01-01'));
    });

    test('Verify Pre-generated SD-JWT', () async {
      final claims = {
        'given_name': 'Harry',
        'family_name': 'Potter',
        'email': 'harry.p@example.com',
        'address': {
          'street': '123 Main St',
          'city': 'Berlin',
          'country': 'DE',
        },
        'birth_date': '1990-01-01'
      };

      final selectiveDisclosureClaims = {
        '_sd': [
          'given_name',
          'email',
          'birth_date',
        ]
      };

      final handler = SdJwtHandlerV1();

      final sdJwt = handler.sign(
        claims: claims,
        disclosureFrame: selectiveDisclosureClaims,
        signer: signer,
      );

      final publicKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_public_key.pem',
      ));

      final publicKey = SdPublicKey(
        publicKeyFile.readAsStringSync(),
        SdJwtSignAlgorithm.es256k,
      );
      final verifier = SDKeyVerifier(publicKey);

      final verifiedSdJwt = handler.verify(
        sdJwt: sdJwt,
        verifier: verifier,
      );

      expect(verifiedSdJwt.claims, isNotEmpty);
      expect(verifiedSdJwt.claims['family_name'], equals('Potter'));
      expect(verifiedSdJwt.claims['given_name'], equals('Harry'));
      expect(verifiedSdJwt.claims['email'], equals('harry.p@example.com'));
      expect(verifiedSdJwt.claims['birth_date'], equals('1990-01-01'));
      expect(verifiedSdJwt.claims['address'], isA<Map>());
      expect(verifiedSdJwt.claims['address']['street'], equals('123 Main St'));
      expect(verifiedSdJwt.claims['address']['city'], equals('Berlin'));
      expect(verifiedSdJwt.claims['address']['country'], equals('DE'));
    });

    test('Test SD-JWT with invalid signature', () async {
      final claims = {
        'given_name': 'Harry',
        'family_name': 'Potter',
      };

      final selectiveDisclosureClaims = {
        '_sd': ['given_name']
      };

      final handler = SdJwtHandlerV1();

      final sdJwt = handler.sign(
        claims: claims,
        disclosureFrame: selectiveDisclosureClaims,
        signer: signer,
      );

      final parts = sdJwt.serialized.split('~');
      final jwtParts = parts[0].split('.');

      String tamperedJwt =
          '${jwtParts[0]}.${jwtParts[1]}.invalidSignatureABCDEFG1234567890';

      if (parts.length > 1) {
        tamperedJwt += '~${parts.sublist(1).join('~')}';
      }

      final publicKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_public_key.pem',
      ));

      final publicKey = SdPublicKey(
        publicKeyFile.readAsStringSync(),
        SdJwtSignAlgorithm.es256k,
      );
      final verifier = SDKeyVerifier(publicKey);

      try {
        handler.decodeAndVerify(
          sdJwtToken: tamperedJwt,
          verifier: verifier,
        );
        fail('Should have thrown an exception for invalid signature');
      } catch (e) {
        expect(e, isNotNull);
      }
    });

    // Test case for SD-JWT with Key Binding (commented out as in original demo)
    /*
    test('Verify SD-JWT with Key Binding', () async {
      // First, create a signed SD-JWT with holder binding
      final claims = {
        'given_name': 'John',
        'family_name': 'Doe',
        'ssn': '123-45-6789',
      };
      
      final selectiveDisclosureClaims = {
        '_sd': ['given_name', 'family_name', 'ssn']
      };
      
      final holderPrivateKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_holder_private_key.pem',
      ));
      
      final holderPublicKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_holder_public_key.pem',
      ));
      
      final holderPrivateKey = SdPrivateKey(
        holderPrivateKeyFile.readAsStringSync(),
        SdJwtAlgorithm.es256k,
      );
      
      final holderPublicKey = SdPublicKey(
        holderPublicKeyFile.readAsStringSync(),
        SdJwtAlgorithm.es256k,
      );
      
      final handler = SdJwtHandlerV1();
      
      // Create the SD-JWT with holder binding
      final sdJwt = await handler.sign(
        claims: claims,
        disclosureFrame: selectiveDisclosureClaims,
        issuerPrivateKey: issuerPrivateKey,
        holderPublicKey: holderPublicKey,
      );
      
      // Add key binding
      final disclosuresToKeep = sdJwt.sdJwtToken.disclosuresDigestIndex.values.toSet();
      
      final sdJwtWithKeyBinding = await handler.signWithKeyBinding(
        sdJwtToken: sdJwt.sdJwtToken,
        disclosuresToKeep: disclosuresToKeep,
        audience: "https://verifier.example.com",
        holderPublicKey: holderPublicKey,
        holderPrivateKey: holderPrivateKey,
      );
      
      // Get the public key for verification
      final publicKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_public_key.pem',
      ));
      
      final publicKey = SdPublicKey(
        publicKeyFile.readAsStringSync(),
        SdJwtAlgorithm.es256k,
      );
      
      // Verify the SD-JWT with key binding
      final verified = await handler.verify(
        sdJwt: sdJwtWithKeyBinding.sdPlusKbJwt.serialized,
        issuerKey: publicKey,
        holderKey: holderPublicKey,
        audience: "https://verifier.example.com",
      );
      
      expect(verified.sdJwt.claims, isNotNull);
      expect(verified.sdJwt.claims['given_name'], equals('John'));
      expect(verified.sdJwt.claims['family_name'], equals('Doe'));
      expect(verified.sdJwt.claims['ssn'], equals('123-45-6789'));
    });
    */

    test('Test SD-JWT with selective disclosure', () async {
      final claims = {
        'given_name': 'Harry',
        'family_name': 'Potter',
        'email': 'harry.p@example.com',
        'address': {
          'street': '123 Main St',
          'city': 'Berlin',
          'country': 'DE',
        },
        'birth_date': '1990-01-01',
        'id_number': '123456789'
      };

      final selectiveDisclosureClaims = {
        '_sd': ['given_name', 'email', 'birth_date', 'id_number']
      };

      final handler = SdJwtHandlerV1();

      final sdJwt = handler.sign(
        claims: claims,
        disclosureFrame: selectiveDisclosureClaims,
        signer: signer,
      );

      final publicKeyFile = File(path.join(
        resourcesPath,
        'secp256k1_sdjwt_test_public_key.pem',
      ));

      final publicKey = SdPublicKey(
        publicKeyFile.readAsStringSync(),
        SdJwtSignAlgorithm.es256k,
      );
      final verifier = SDKeyVerifier(publicKey);

      final verifiedSdJwt = handler.verify(
        sdJwt: sdJwt,
        verifier: verifier,
      );

      expect(verifiedSdJwt.claims['given_name'], equals('Harry'));
      expect(verifiedSdJwt.claims['family_name'], equals('Potter'));
      expect(verifiedSdJwt.claims['email'], equals('harry.p@example.com'));
      expect(verifiedSdJwt.claims['birth_date'], equals('1990-01-01'));
      expect(verifiedSdJwt.claims['id_number'], equals('123456789'));
      expect(verifiedSdJwt.claims['address'], isA<Map>());
      expect(verifiedSdJwt.claims.keys, containsAll(claims.keys));
    });
  });
}
