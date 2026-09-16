import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

/// VC Data Integrity §2.1 requires `created` to be an XMLSCHEMA11-2
/// `dateTimeStamp`: "either in Universal Coordinated Time (UTC), denoted by a Z
/// at the end of the value, or with a time zone offset relative to UTC".
///
/// Generators previously stamped `created` with `DateTime.now()`, a *local*
/// DateTime, whose `toIso8601String()` carries no offset at all — so every
/// proof they emitted was non-conforming. That is not only a strictness
/// problem: §2.1 says a processor that does accept an offset-less value must
/// interpret it *as UTC*, so a signer outside UTC produced a `created` that a
/// conforming reader would place hours away from the real signing time.
///
/// This fails on a UTC machine too. The missing `Z` follows from
/// `DateTime.isUtc`, which is false for `DateTime.now()` whatever the local
/// zone is — so a CI runner on UTC exercises it exactly as a laptop does.
///
/// Each test also re-verifies the proof. `created` feeds both the signed proof
/// configuration and the emitted JSON; a fix applied to only one of the two
/// would produce a conforming timestamp and an invalid signature.
void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );
  final edSigner = await initEdSigner(seed);
  final p256Signer = await initP256Signer(seed);
  final secp256k1Signer = await initSigner(seed);

  /// A `dateTimeStamp` as §2.1 permits it: a trailing `Z`, or an explicit
  /// `±hh:mm` offset. The generators now emit the former.
  final dateTimeStamp = RegExp(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$',
  );

  Map<String, dynamic> jcsDocument(String issuer) => {
    'id': 'urn:uuid:created-timestamp-test',
    'issuer': issuer,
    'credentialSubject': {'id': 'did:example:subject'},
  };

  VcDataModelV1 rdfcCredential(String issuer) => VcDataModelV1.fromMutable(
    MutableVcDataModelV1(
      context: MutableJsonLdContext.fromJson([
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/data-integrity/v2',
      ]),
      id: Uri.parse('uuid:created-timestamp-test'),
      type: {'VerifiableCredential'},
      credentialSubject: [
        MutableCredentialSubject({'id': 'did:example:subject'}),
      ],
      issuanceDate: DateTime.utc(2026, 1, 1),
      issuer: Issuer.uri(issuer),
    ),
  );

  void expectConformingCreated(Map<String, dynamic> proof) {
    final created = proof['created'];
    expect(created, isA<String>());
    expect(
      created,
      matches(dateTimeStamp),
      reason:
          'VC Data Integrity §2.1: created MUST be a dateTimeStamp '
          '(UTC with Z, or an explicit offset); got "$created"',
    );
    // Specifically UTC: the generators take the current instant, and an offset
    // other than zero would still leave `created` dependent on the signer's
    // local zone.
    expect(created, endsWith('Z'));
  }

  group('proof `created` is a UTC dateTimeStamp (VC Data Integrity §2.1)', () {
    test('eddsa-jcs-2022 (shared JCS generator)', () async {
      final doc = jcsDocument(edSigner.did);
      final proof = await DataIntegrityEddsaJcsGenerator(
        signer: edSigner,
      ).generate(Map.of(doc));
      final signed = {...doc, 'proof': proof.toJson()};

      expectConformingCreated(signed['proof'] as Map<String, dynamic>);

      final result = await DataIntegrityEddsaJcsVerifier(
        verifierDid: edSigner.did,
      ).verify(signed);
      expect(result.isValid, true, reason: '${result.errors}');
    });

    test('ecdsa-jcs-2019 (shared JCS generator)', () async {
      final doc = jcsDocument(p256Signer.did);
      final proof = await DataIntegrityEcdsaJcsGenerator(
        signer: p256Signer,
      ).generate(Map.of(doc));
      final signed = {...doc, 'proof': proof.toJson()};

      expectConformingCreated(signed['proof'] as Map<String, dynamic>);

      final result = await DataIntegrityEcdsaJcsVerifier(
        verifierDid: p256Signer.did,
      ).verify(signed);
      expect(result.isValid, true, reason: '${result.errors}');
    });

    test('eddsa-rdfc-2022', () async {
      final issued = await LdVcDm1Suite().issue(
        unsignedData: rdfcCredential(edSigner.did),
        proofGenerator: DataIntegrityEddsaRdfcGenerator(signer: edSigner),
      );
      final json = issued.toJson();

      expectConformingCreated(json['proof'] as Map<String, dynamic>);

      final result = await DataIntegrityEddsaRdfcVerifier(
        issuerDid: edSigner.did,
      ).verify(json);
      expect(result.isValid, true, reason: '${result.errors}');
    });

    test('ecdsa-rdfc-2019', () async {
      final issued = await LdVcDm1Suite().issue(
        unsignedData: rdfcCredential(p256Signer.did),
        proofGenerator: DataIntegrityEcdsaRdfcGenerator(signer: p256Signer),
      );
      final json = issued.toJson();

      expectConformingCreated(json['proof'] as Map<String, dynamic>);

      final result = await DataIntegrityEcdsaRdfcVerifier(
        issuerDid: p256Signer.did,
      ).verify(json);
      expect(result.isValid, true, reason: '${result.errors}');
    });

    test('EcdsaSecp256k1Signature2019', () async {
      final issued = await LdVcDm1Suite().issue(
        unsignedData: rdfcCredential(secp256k1Signer.did),
        proofGenerator: Secp256k1Signature2019Generator(
          signer: secp256k1Signer,
        ),
      );
      final json = issued.toJson();

      expectConformingCreated(json['proof'] as Map<String, dynamic>);

      final result = await Secp256k1Signature2019Verifier(
        issuerDid: secp256k1Signer.did,
      ).verify(json);
      expect(result.isValid, true, reason: '${result.errors}');
    });
  });
}
