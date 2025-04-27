import 'package:elliptic/elliptic.dart' as ec;
import 'package:ssi/src/didcomm/_ecdh1pu.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/ssi.dart';

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
    ec.Curve c = getEllipticCurveByPublicKey(receiverPublicKey);
    ec.PublicKey epkPublicKey = publicKeyFromPoint(
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
}
