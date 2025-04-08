import 'dart:developer' as developer;

import 'package:ssi/src/credentials/parsers/vc_data_model_v1_with_proof_parser.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/verifiable_credential.dart';
import '../parsers/jwt_vc_data_model_v1_parser.dart';
import '../parsers/sdjwt_data_model_v2_parser.dart';
import '../parsers/vc_data_model_parser.dart';
import '../parsers/vc_data_model_v2_with_proof_parser.dart';

/// Factory class supporting multiple parsers to convert data into a [VerifiableCredential]
///
/// This factory supports multiple credential data model parsers, including:
///
/// - [VcDataModelV1WithProofParser]
/// - [VcDataModelV2WithProofParser]
/// - [JwtVcDataModelV1Parser]
/// - [SdJwtDataModelV2Parser]
///
final class VerifiableCredentialFactory {
  static final _credentialDataModelParsers = <VcDataModelParser>[
    VcDataModelV1WithProofParser(),
    VcDataModelV2WithProofParser(),
    JwtVcDataModelV1Parser(),
    SdJwtDataModelV2Parser(),
  ];

  /// Returns a [VerifiableCredential] instance.
  ///
  /// ### Exceptions
  /// - [SsiExceptionType.unableToParseVerifiableCredential] —
  ///   Thrown when the input does not conform to any known verifiable credential format.
  ///
  /// ### Example
  /// ```dart
  /// final credential = VerifiableCredentialFactory.create(jsonData);
  /// print(credential.id);
  /// ```
  static VerifiableCredential create(Object rawData) {
    developer.log('Starting to parse VerifiableCredential',
        name: 'VerifiableCredentialFactory');
    for (final parser in _credentialDataModelParsers) {
      if (parser.canParse(rawData)) {
        try {
          developer.log('Successfully parsed VC using ${parser.runtimeType}',
              name: 'VerifiableCredentialFactory');
          return parser.parse(rawData);
        } catch (error, stackTrace) {
          developer.log('Parser ${parser.runtimeType} failed',
              name: 'VerifiableCredentialFactory',
              error: error,
              stackTrace: stackTrace);
          Error.throwWithStackTrace(
              SsiException(
                  message: 'Unknown VC Data Model',
                  code: SsiExceptionType.unableToParseVerifiableCredential.code,
                  originalMessage: error.toString()),
              stackTrace);
        }
      }
    }

    developer.log('No available parser could handle the data',
        name: 'VerifiableCredentialFactory');

    Error.throwWithStackTrace(
        SsiException(
            message: 'Unknown VC Data Model',
            code: SsiExceptionType.unableToParseVerifiableCredential.code),
        StackTrace.current);
  }
}
