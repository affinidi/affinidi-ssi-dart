import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('areJwksEqual', () {
    group('EC keys', () {
      test('identical P-256 keys should be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });

      test('P-256 keys with different x coordinate should not be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'DIFFERENT_X_VALUE',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });

      test('P-256 keys with different y coordinate should not be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'DIFFERENT_Y_VALUE',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });

      test('P-256 keys with different curve should not be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'P-384',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });

      test('identical secp256k1 keys should be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'secp256k1',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'secp256k1',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });
    });

    group('OKP keys', () {
      test('identical Ed25519 keys should be equal', () {
        final jwk1 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });

      test('Ed25519 keys with different x should not be equal', () {
        final jwk1 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': 'DIFFERENT_X_VALUE',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });

      test('Ed25519 keys with different curve should not be equal', () {
        final jwk1 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'X25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });
    });

    group('unsupported key types', () {
      test('RSA keys should return false (unsupported)', () {
        final jwk1 = {
          'kty': 'RSA',
          'n': 'MODULUS',
          'e': 'AQAB',
        };
        final jwk2 = {
          'kty': 'RSA',
          'n': 'MODULUS',
          'e': 'AQAB',
        };

        // RSA keys are not supported by this library
        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });

      test('oct keys should return false (unsupported)', () {
        final jwk1 = {
          'kty': 'oct',
          'k': 'GawgguFyGrWKav7AX4VKUg',
        };
        final jwk2 = {
          'kty': 'oct',
          'k': 'GawgguFyGrWKav7AX4VKUg',
        };

        // Symmetric keys are not supported by this library
        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });
    });

    group('different key types', () {
      test('EC and OKP keys should not be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });
    });

    group('metadata fields', () {
      test('same key with different kid should be equal', () {
        final jwk1 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
          'kid': 'key-1',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
          'kid': 'key-2',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });

      test('same key with different alg should be equal', () {
        final jwk1 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
          'alg': 'EdDSA',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
          'alg': 'Ed25519',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });

      test('same key with different use should be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
          'use': 'sig',
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
          'use': 'enc',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });

      test('same key with different key_ops should be equal', () {
        final jwk1 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
          'key_ops': ['sign'],
        };
        final jwk2 = {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
          'y': 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
          'key_ops': ['verify'],
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });

      test('same key with one missing metadata should be equal', () {
        final jwk1 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        };
        final jwk2 = {
          'kty': 'OKP',
          'crv': 'Ed25519',
          'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
          'kid': 'key-1',
          'alg': 'EdDSA',
          'use': 'sig',
        };

        expect(areJwksEqual(jwk1, jwk2), isTrue);
      });
    });

    group('unknown key types', () {
      test('unknown key type should return false', () {
        final jwk1 = {
          'kty': 'UNKNOWN',
          'x': 'some-value',
        };
        final jwk2 = {
          'kty': 'UNKNOWN',
          'x': 'some-value',
        };

        expect(areJwksEqual(jwk1, jwk2), isFalse);
      });
    });
  });
}
