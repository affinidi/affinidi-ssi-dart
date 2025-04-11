import '../models/verifiable_credential.dart';
import 'ld_base_suite.dart';
import 'ld_vc_data_model_v2.dart';

class LdVcDm2Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm2Suite<LdVcDm1Options> extends LdBaseSuite {
  static const String _v2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

  LdVcDm2Suite()
      : super(
          parser: LdVcDataModelV2.parse,
          contextUrl: _v2ContextUrl,
        );
}
