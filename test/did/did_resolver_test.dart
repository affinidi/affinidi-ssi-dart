import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/did/did_key.dart';
import 'package:ssi/src/did/did_peer.dart';
import 'package:ssi/src/did/did_resolver.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:ssi/src/wallet/bip32_ed25519_wallet.dart';
import 'package:ssi/src/wallet/bip32_wallet.dart';
import 'package:test/test.dart';

void main() {
  group("When resolving did document", () {
    group("using did:key,", () {
      test("it resolves succesfully", () async {
        final seed = hexDecode(
          'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
        );
        final wallet = Bip32Wallet.fromSeed(seed);
        final rootKeyId = "0-0";
        final keyPair = await wallet.getKeyPair(rootKeyId);
        final doc = await DidKey.create([keyPair]);

        final expectedDidDoc = jsonDecode(
            '{"@context":["https://www.w3.org/ns/did/v1","https://ns.did.ai/suites/multikey-2021/v1/"],"id":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","verificationMethod":[{"id":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","controller":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":"Secp256k1Key2021","publicKeyMultibase":"zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"}],"authentication":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"capabilityDelegation":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"capabilityInvocation":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"keyAgreement":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"assertionMethod":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"]}');

        final resolvedDidDocument = await resolveDidDocument(doc.id);
        expect(resolvedDidDocument.toJson(), expectedDidDoc);
      });
    });

    group("using did:peer,", () {
      test("it resolves successfully", () async {
        final seed = hexDecode(
          'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        );
        final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
        final rootKeyId = "0-0";
        final keyPair = await wallet.getKeyPair(rootKeyId);
        final doc = await DidPeer.create([keyPair]);

        final expectedDidDoc = jsonDecode(
            '{"@context": ["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"], "id":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","verificationMethod":[{"id":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","controller":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"}],"authentication":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"capabilityDelegation":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"capabilityInvocation":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"keyAgreement":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#z6LSrY3Na7Bkq7f3ktzajpR7vQ4YCjyw9KCT1Y2tnjLLZsV5"],"assertionMethod":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"]}');

        final resolvedDidDoc = await resolveDidDocument(doc.id);

        expect(resolvedDidDoc.toJson(), expectedDidDoc);
      });
    });

    group("uding did:web,", () {
      test("it throws exception on non-200 responces", () {
        final did = 'did:web:example.com';

        expectLater(
          resolveDidDocument(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
        );
      });
    });

    group("using resolver address", () {
      test("it throws undable to resolve did when resolverAddress null", () {
        final did = "did:test";

        expectLater(
          resolveDidDocument(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });

      test("it throws exception on non-200 responces", () {
        final did = "did:test";
        final resolverAddress = "example.com";

        expectLater(
          resolveDidDocument(did, resolverAddress: resolverAddress),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });
    });
  });
}
