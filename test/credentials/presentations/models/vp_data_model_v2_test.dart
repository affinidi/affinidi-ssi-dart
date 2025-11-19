import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('VpDataModelV2 Validation Tests', () {
    test('validate() throws when type is empty', () {
      expect(
        () => VpDataModelV2(
          context: [dmV2ContextUrl],
          type: {},
          holder: Holder.uri('did:example:holder'),
          verifiableCredential: [],
          proof: [],
        ),
        throwsA(predicate((e) =>
            e is SsiException &&
            e.code == SsiExceptionType.invalidJson.code &&
            e.message.contains('`type` property is mandatory'))),
      );
    });

    test('validate() throws when `VerifiablePresentation` is missing in type',
        () {
      expect(
        () => VpDataModelV2(
          context: [dmV2ContextUrl],
          type: {'CustomPresentation'},
          holder: Holder.uri('did:example:holder'),
          verifiableCredential: [],
          proof: [],
        ),
        throwsA(predicate((e) =>
            e is SsiException &&
            e.code == SsiExceptionType.invalidJson.code &&
            e.message
                .contains('MUST include the value "VerifiablePresentation"'))),
      );
    });

    test('validate() succeeds when `type` contains VerifiablePresentation', () {
      final vp = VpDataModelV2(
        context: [dmV2ContextUrl],
        type: {'VerifiablePresentation'},
        holder: Holder.uri('did:example:holder'),
        verifiableCredential: [],
        proof: [],
      );
      expect(vp.type.contains('VerifiablePresentation'), isTrue);
    });

    test(
        'validate() succeeds with multiple types including VerifiablePresentation',
        () {
      final vp = VpDataModelV2(
        context: [dmV2ContextUrl],
        type: {'VerifiablePresentation', 'CustomPresentation'},
        holder: Holder.uri('did:example:holder'),
        verifiableCredential: [],
        proof: [],
      );
      expect(vp.type.contains('VerifiablePresentation'), isTrue);
      expect(vp.type.contains('CustomPresentation'), isTrue);
    });
  });
}
