import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('When verifying a JWT VC', () {
    test('it rejects a signer DID that differs from the issuer DID', () async {
      final signer = await initSigner(
        Uint8List.fromList(List.generate(32, (index) => index + 1)),
      );
      final suite = JwtDm1Suite();
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:issuer-mismatch',
        'type': ['VerifiableCredential'],
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'id': 'did:example:subject'},
      })
        ..issuer = MutableIssuer.uri(signer.did);
      final issuedCredential = await suite.issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        signer: signer,
      );

      final segments = issuedCredential.serialized.split('.');
      final payload = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(segments[1]))),
      ) as Map<String, dynamic>;
      payload['iss'] = 'did:example:trusted-issuer';
      final encodedPayload = base64Url
          .encode(utf8.encode(jsonEncode(payload)))
          .replaceAll('=', '');
      final toSign = ascii.encode('${segments[0]}.$encodedPayload');
      final encodedSignature =
          base64Url.encode(await signer.sign(toSign)).replaceAll('=', '');
      final forgedCredential = suite.parse(
        '${segments[0]}.$encodedPayload.$encodedSignature',
      );

      expect(
        () => suite.verifyIntegrity(forgedCredential),
        throwsA(
          isA<SsiException>()
              .having(
                (exception) => exception.code,
                'code',
                SsiExceptionType.invalidJson.code,
              )
              .having(
                (exception) => exception.message,
                'message',
                'Issuer mismatch',
              ),
        ),
      );
    });
  });
}
