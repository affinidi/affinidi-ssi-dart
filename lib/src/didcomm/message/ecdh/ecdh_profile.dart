import 'dart:convert';
import 'dart:typed_data';

import 'package:elliptic/elliptic.dart' as ec;

import 'package:ssi/src/didcomm/message/ecdh/ecdh_1pu.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/key_pair/public_key.dart';

class ECDHProfile {
  static ECDH1PU_Elliptic buildElliptic({
    required PublicKey receiverPublicKey,
    required ec.PublicKey senderPublicKey,
    required List<int> authenticationTag,
    required KeyWrapAlgorithm keyWrapAlgorithm,
    required String apu,
    required String apv,
    required Map epk,
  }) {
    final c = getEllipticCurveByPublicKey(receiverPublicKey);
    final epkPublicKey = publicKeyFromPoint(
      x: epk['x'],
      y: epk['y'],
      curve: c,
    );

    return ECDH1PU_Elliptic(
      public1: epkPublicKey,
      public2: senderPublicKey,
      authenticationTag: authenticationTag,
      keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
      apu: apu,
      apv: apv,
    );
  }

  static ECDH1PU_Elliptic buildEllipticWithReceiverCurve({
    required ec.Curve curve,
    required ec.PublicKey senderPublicKey,
    required List<int> authenticationTag,
    required KeyWrapAlgorithm keyWrapAlgorithm,
    required String apu,
    required String apv,
    required Map epk,
  }) {
    final epkPublicKey = publicKeyFromPoint(
      x: epk['x'],
      y: epk['y'],
      curve: curve,
    );

    return ECDH1PU_Elliptic(
      public1: epkPublicKey,
      public2: senderPublicKey,
      authenticationTag: authenticationTag,
      keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
      apu: apu,
      apv: apv,
    );
  }

  static ECDH1PU_X25519 buildX25519({
    required Uint8List senderPublicKeyBytes,
    required List<int> authenticationTag,
    required KeyWrapAlgorithm keyWrapAlgorithm,
    required String apu,
    required String apv,
    required Map epk,
  }) {
    final epkPublicKeyBytes = base64Decode(addPaddingToBase64(epk['x']));

    return ECDH1PU_X25519(
      public1: epkPublicKeyBytes,
      public2: senderPublicKeyBytes,
      authenticationTag: authenticationTag,
      keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
      apu: apu,
      apv: apv,
    );
  }
}
