import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fakes/static_did_resolver.dart';
import '../../test_utils.dart';

void main() {
  group('When verifying a JWT VC', () {
    test('it rejects an issuer not identified by the resolved document',
        () async {
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
      final resolver = StaticDidResolver(DidKey.resolve(signer.did));

      expect(
        () => suite.verifyIntegrity(
          forgedCredential,
          didResolver: resolver,
        ),
        throwsA(
          isA<SsiException>().having(
            (exception) => exception.code,
            'code',
            SsiExceptionType.invalidDidDocument.code,
          ),
        ),
      );
    });

    test('it rejects issuer identity based only on alsoKnownAs', () async {
      final keyPair = await Bip32Wallet.fromSeed(
        Uint8List.fromList(List.generate(32, (index) => index + 33)),
      ).generateKey(keyId: "m/44'/60'/0'/0'/0'");
      final generatedDocument = DidKey.generateDocument(keyPair.publicKey);
      const issuerDid = 'did:webvh:QmExample:example.com?versionId=1-QmExample';
      const issuerAlias = 'did:webvh:QmExample:example.com';
      const canonicalDid = 'did:web:example.com';
      const kid = '$canonicalDid#auth-1';
      final verificationMethod = Map<String, dynamic>.from(
        generatedDocument.verificationMethod.single.toJson(),
      )
        ..['id'] = kid
        ..['controller'] = canonicalDid;
      final didDocument = DidDocument.fromJson({
        '@context': 'https://www.w3.org/ns/did/v1',
        'id': canonicalDid,
        'alsoKnownAs': [issuerAlias],
        'verificationMethod': [verificationMethod],
        'assertionMethod': [kid],
      });
      final signer = DidSigner(
        did: issuerDid,
        didKeyId: kid,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
      );
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:webvh-alias',
        'type': ['VerifiableCredential'],
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'id': 'did:example:subject'},
      })
        ..issuer = MutableIssuer.uri(issuerDid);
      final issuedCredential = await JwtDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        signer: signer,
      );
      final resolver = StaticDidResolver(didDocument);

      expect(
        () => JwtDm1Suite().verifyIntegrity(
          issuedCredential,
          didResolver: resolver,
        ),
        throwsA(
          isA<SsiException>().having(
            (exception) => exception.code,
            'code',
            SsiExceptionType.invalidDidDocument.code,
          ),
        ),
      );

      expect(resolver.lastDid, issuerDid);
    });

    group('and the signing key is only a verification method', () {
      late DidSigner signer;
      late DidDocument didDocument;
      late JwtVcDataModelV1 issuedCredential;

      setUp(() async {
        signer = await initSigner(
          Uint8List.fromList(List.generate(32, (index) => index + 97)),
        );
        final documentJson = DidKey.resolve(signer.did).toJson()
          ..remove('assertionMethod');
        didDocument = DidDocument.fromJson(documentJson);
        final credential = MutableVcDataModelV1.fromJson({
          '@context': [dmV1ContextUrl],
          'id': 'urn:uuid:verification-method-only',
          'type': ['VerifiableCredential'],
          'issuanceDate': '2023-01-01T12:00:00Z',
          'credentialSubject': {'id': 'did:example:subject'},
        })
          ..issuer = MutableIssuer.uri(signer.did);
        issuedCredential = await JwtDm1Suite().issue(
          unsignedData: VcDataModelV1.fromMutable(credential),
          signer: signer,
        );
      });

      test('it accepts the key by default for VCDM 1.1 compatibility',
          () async {
        final isValid = await JwtDm1Suite().verifyIntegrity(
          issuedCredential,
          didResolver: StaticDidResolver(didDocument),
        );

        expect(isValid, isTrue);
      });

      test('it rejects the key when assertionMethod is required', () async {
        expect(
          () => JwtDm1Suite(requireAssertionMethod: true).verifyIntegrity(
            issuedCredential,
            didResolver: StaticDidResolver(didDocument),
          ),
          throwsA(
            isA<SsiException>().having(
              (exception) => exception.code,
              'code',
              SsiExceptionType.invalidDidDocument.code,
            ),
          ),
        );
      });
    });

    test('it preserves a WebVH version selector from the signing key',
        () async {
      final keyPair = Ed25519KeyPair.fromSeed(
        Uint8List.fromList(List.generate(32, (index) => index + 65)),
      );
      const issuerDid = 'did:webvh:QmExample:example.com';
      const versionedDid = '$issuerDid?versionId=1-QmExample';
      const kid = '$versionedDid#auth-1';
      const documentKid = '$issuerDid#auth-1';
      final generatedDocument = DidKey.generateDocument(keyPair.publicKey);
      final verificationMethod = Map<String, dynamic>.from(
        generatedDocument.verificationMethod.first.toJson(),
      )
        ..['id'] = documentKid
        ..['controller'] = issuerDid;
      final didDocument = DidDocument.fromJson({
        '@context': 'https://www.w3.org/ns/did/v1',
        'id': issuerDid,
        'verificationMethod': [verificationMethod],
        'assertionMethod': [documentKid],
      });
      final signer = DidSigner(
        did: issuerDid,
        didKeyId: kid,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ed25519,
      );
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:webvh-versioned-key',
        'type': ['VerifiableCredential'],
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'id': 'did:example:subject'},
      })
        ..issuer = MutableIssuer.uri(issuerDid);
      final issuedCredential = await JwtDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        signer: signer,
      );
      final resolver = StaticDidResolver(didDocument);

      final isValid = await JwtDm1Suite().verifyIntegrity(
        issuedCredential,
        didResolver: resolver,
      );

      expect(isValid, isTrue);
      expect(resolver.lastDid, versionedDid);
    });
  });
}
