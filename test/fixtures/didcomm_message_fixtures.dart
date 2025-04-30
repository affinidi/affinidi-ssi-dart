import 'package:ssi/ssi.dart';

class DidcommMessageFixtures {
  static getMessage({required String to, String? from}) =>
      DidcommPlaintextMessage(
        id: '2fb19055-581d-488e-b357-9d026bee98fc',
        to: [to],
        from: from,
        type: 'type',
        body: {"foo": 'bar'},
      );
}
