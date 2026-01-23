import 'dart:convert';
import 'dart:io';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('Revocation Issuance', () {
    late DidSigner signer;

    setUp(() async {
      final seed = hexDecode(
        // deterministic seed
        'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
      );
      signer = await initSigner(seed);
    });

    test('LD VC issuance preserves credentialStatus', () async {
      final unsigned = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld',
          'https://w3id.org/vc-revocation-list-2020/v1',
        ]),
        id: Uri.parse('uuid:ld-revocable'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        holder: MutableHolder.uri('did:example:holder123'),
        issuanceDate: DateTime.now().toUtc(),
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Alice',
            'Lname': 'Example',
            'Age': '29',
            'Address': '123 Demo Street',
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
        credentialStatus: MutableCredentialStatusV1({
          'id': 'urn:uuid:revocation-list-0',
          'type': 'RevocationList2020Status',
          'revocationListIndex': '0',
          'revocationListCredential': 'https://example.org/revocation-list',
        }),
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsigned),
        proofGenerator: proofGenerator,
      );

      final json = issued.toJson();
      // Proof exists
      expect(json['proof'], isNotNull);
      // credentialStatus preserved
      expect(json['credentialStatus'], isNotNull);
      expect(json['credentialStatus']['revocationListIndex'], '0');
      expect(json['credentialStatus']['type'], 'RevocationList2020Status');
    });

    test('JWT VC issuance preserves credentialStatus', () async {
      final unsigned = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld',
          'https://w3id.org/vc-revocation-list-2020/v1',
        ]),
        id: Uri.parse('uuid:jwt-revocable'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        holder: MutableHolder.uri('did:example:holder123'),
        issuanceDate: DateTime.now().toUtc(),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:holder123',
            'Fname': 'Alice',
            'Lname': 'Example',
            'Age': '29',
            'Address': '123 Demo Street',
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
        credentialStatus: MutableCredentialStatusV1({
          'id': 'urn:uuid:revocation-list-0',
          'type': 'RevocationList2020Status',
          'revocationListIndex': '0',
          'revocationListCredential': 'https://example.org/revocation-list',
        }),
      );

      final suite = JwtDm1Suite();
      final issuedJwt = await suite.issue(
        unsignedData: VcDataModelV1.fromMutable(unsigned),
        signer: signer,
      );

      final payload = issuedJwt.jws.payload;
      expect(payload['vc'], isNotNull);
      expect(payload['vc']['credentialStatus'], isNotNull);
      expect(payload['vc']['credentialStatus']['revocationListIndex'], '0');
      expect(payload['vc']['credentialStatus']['type'],
          'RevocationList2020Status');
    });

    test('Revoked credential verification fails after list update', () async {
      // Bitstring: first bit 1 => index 0 revoked
      final bitstring = [0x01]; // 0b0000_0001, index 0 is set (LSB)
      final compressed = gzip.encode(bitstring);
      final encodedList = base64Url.encode(compressed);

      final revocationListCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        'id': 'https://example.org/revocation-list',
        'type': ['VerifiableCredential', 'RevocationList2020'],
        'issuer': signer.did,
        'credentialSubject': {
          'id': 'https://example.org/revocation-list#list',
          'type': 'RevocationList2020',
          'encodedList': encodedList,
        }
      };

      final unsigned = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld',
          'https://w3id.org/vc-revocation-list-2020/v1',
        ]),
        id: Uri.parse('uuid:revoked'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        holder: MutableHolder.uri('did:example:holder123'),
        issuanceDate: DateTime.now().toUtc(),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:holder123',
            'Fname': 'Alice',
            'Lname': 'Example',
            'Age': '29',
            'Address': '123 Demo Street',
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
        credentialStatus: MutableCredentialStatusV1({
          'id': 'urn:uuid:revocation-list-0',
          'type': 'RevocationList2020Status',
          'revocationListIndex': '0',
          'revocationListCredential': 'https://example.org/revocation-list',
        }),
      );

      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsigned),
        proofGenerator: Secp256k1Signature2019Generator(signer: signer),
      );

      final serialized = jsonEncode(issued.toJson());
      final parsed = UniversalParser.parse(serialized);

      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async => revocationListCredential,
      );

      final result = await verifier.verify(parsed);
      expect(result.isValid, false);
      expect(
        result.errors,
        contains(
          '${SsiExceptionType.revokedVC.code} ${parsed.id} for status urn:uuid:revocation-list-0',
        ),
      );
    });
  });
}
