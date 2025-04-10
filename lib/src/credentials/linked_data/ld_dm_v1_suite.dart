import 'package:ssi/src/credentials/linked_data/ld_base_suite.dart';
import 'package:ssi/src/credentials/linked_data/ld_vc_data_model_v1.dart';

import '../models/verifiable_credential.dart';

class LdVcDm1Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm1Suite<LdVcDm1Options> extends LdBaseSuite {
  static const _v1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

  LdVcDm1Suite()
      : super(
          parser: LdVcDataModelV1.parse,
          contextUrl: _v1ContextUrl,
        );
}
