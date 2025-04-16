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

import '../fixtures/did_document_fixtures.dart';

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
        final doc = await DidKey.create(keyPair);

        final expectedDidDoc =
            jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);

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

        final expectedDidDoc =
            jsonDecode(DidDocumentFixtures.didDocumentWithControllerPeer);

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
        final resolverAddress = "https://example.com";

        expectLater(
          resolveDidDocument(did, resolverAddress: resolverAddress),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });
    });
  });
}
