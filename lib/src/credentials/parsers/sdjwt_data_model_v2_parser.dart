import 'package:sdjwt/sdjwt.dart';
import 'package:ssi/src/credentials/parsers/vc_data_model_parser.dart';
import 'package:ssi/src/credentials/parsers/vc_data_model_v2_with_proof_parser.dart';

import '../models/v2/sdjwt_data_model_v2.dart';
import '../models/verifiable_credential.dart';

/// Class to parse and convert a json representation of a [SdjwtDataModelV2]
final class SdJwtDataModelV2Parser extends VcDataModelParser<String, SdjwtDataModelV2> {

final vcdm2Parser = VcDataModelV2WithProofParser();
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  @override
  bool canParse(String data) {
    if(data.trim().isEmpty){
      return false;
    }
    return true;
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  SdjwtDataModelV2 parse(String data) {
    SdJwt jwt = SdJwt.parse(data);
    final vcdm = vcdm2Parser.parse(jwt.payload);
    return SdjwtDataModelV2(jwt, vcdm);
  }
}
