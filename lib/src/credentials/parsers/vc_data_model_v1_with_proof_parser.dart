import '../models/v1/parsed_vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import 'vc_data_model_parser.dart';

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class VcDataModelV1WithProofParser extends VcDataModelParser<Map<String, dynamic>, ParsedVcDataModelV1> {
  static const _v1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

  bool _hasV1Context(Map<String, dynamic> data) {
    final context = data[VcDataModelV1Key.context.key];
    return (context is List) && context.contains(_v1ContextUrl);
  }

  /// Checks if the [data] provided matches the right criteria to attempt a parse
  @override
  bool canParse(Map<String, dynamic> data) {
    if (!_hasV1Context(data)) return false;

    return data.containsKey(VcDataModelV1Key.proof.key);
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  ParsedVcDataModelV1 parse(Map<String, dynamic> data) {
    return ParsedVcDataModelV1(data);
  }
}
