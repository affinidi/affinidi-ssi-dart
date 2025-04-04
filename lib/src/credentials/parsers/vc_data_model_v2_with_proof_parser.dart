import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/v2/parsed_vc_data_model_v2.dart';
import '../models/vc_data_model_v2_key.dart';
import '../models/verifiable_credential.dart';
import 'vc_data_model_parser.dart';

//white paper reference: https://www.w3.org/TR/vc-data-model-2.0/

/// Class to parse and convert a json representation of a [VerifiableCredential]
class VcDataModelV2WithProofParser extends VcDataModelParser<Map<String, dynamic>, ParsedVcDataModelV2> {
  static const _v2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

  bool _hasV2Context(Map<String, dynamic> data) {
    final context = data[VcDataModelV2Key.context.key];
    return (context is List) && context.contains(_v2ContextUrl);
  }

  /// Checks if the [data] provided matches the right criteria to attempt a parse
  @override
  bool canParse(Map<String, dynamic> data) {
    if (!_hasV2Context(data)) return false;
    return data.containsKey(VcDataModelV2Key.proof.key);
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  ParsedVcDataModelV2 parse(Map<String, dynamic> data) {
    if (!canParse(data)) {
      throw SsiException(
        message: 'Unable to parse the input',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }

    try {
      // Validate the data model
      validate(data);
      // Create and return the parsed credential
      return ParsedVcDataModelV2(data);
    } catch (e) {
      throw SsiException(
        message: 'Invalid VC Data Model 2.0 format: ${e.toString()}',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }
  }


  /// Validates if the provided data contains all required properties
  static void validate(Map<String, dynamic> data) {
    final requiredProperties = [
      VcDataModelV2Key.context.key,
      VcDataModelV2Key.id.key,
      VcDataModelV2Key.type.key,
      VcDataModelV2Key.issuer.key,
      VcDataModelV2Key.credentialSubject.key,
      VcDataModelV2Key.validFrom.key,
    ];

    for (final property in requiredProperties) {
      if (!data.containsKey(property)) {
        throw FormatException('Missing required property: $property');
      }
    }

    final context = data[VcDataModelV2Key.context.key];
    if (context is! List ||
        !context.contains('https://www.w3.org/ns/credentials/v2')) {
      throw FormatException('Invalid context: must include v2 context URL');
    }

    final type = data[VcDataModelV2Key.type.key];
    if (type is! List || !type.contains('VerifiableCredential')) {
      throw FormatException('Invalid type: must include VerifiableCredential');
    }

    final credentialSubject = data[VcDataModelV2Key.credentialSubject.key];
    if (credentialSubject is! Map) {
      throw FormatException('Invalid credentialSubject: must be an object');
    }

    final validFrom = data[VcDataModelV2Key.validFrom.key];
    if (validFrom is! String) {
      throw FormatException('Invalid validFrom: must be a string');
    }
    try {
      DateTime.parse(validFrom);
    } catch (e) {
      throw FormatException('Invalid validFrom: must be a valid ISO 8601 date / dateTimeStamp');
    }

    final validUntil = data[VcDataModelV2Key.validUntil.key];
    if (validUntil != null) {
      if (validUntil is! String) {
        throw FormatException('Invalid validUntil: must be a string');
      }
      try {
        DateTime.parse(validUntil);
      } catch (e) {
        throw FormatException(
            'Invalid validUntil: must be a valid ISO 8601 date / dateTimeStamp');
      }
    }

    final credentialSchema = data[VcDataModelV2Key.credentialSchema.key];
    if (credentialSchema != null) {
      if (credentialSchema is! List && credentialSchema is! Map) {
        throw FormatException(
            'Invalid credentialSchema: must be an object or array');
      }
    }
  }
}
