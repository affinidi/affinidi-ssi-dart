import '../../../ssi.dart';
import '../models/revocation_list_2020.dart';

/// Registry of all supported Verifiable Credential suites.
///
/// This class provides access to the various suite implementations that can
/// be used for working with different types of Verifiable Credentials.
class VcSuites {
  /// List of all available credential suite implementations.
  ///
  /// Includes support for:
  /// - Linked Data credentials (v1 and v2)
  /// - JWT-based credentials (v1)
  /// - SD-JWT credentials (v2)
  static final suites = <VerifiableCredentialSuite>[
    EnvelopedVcDm2Suite(),
    LdVcDm1Suite(),
    LdVcDm2Suite(),
    JwtDm1Suite(),
    SdJwtDm2Suite(),
  ];

  /// Returns the appropriate suite for the given credential.
  ///
  /// [vc] - The parsed verifiable credential to find a suite for.
  ///
  /// Returns the matching VerifiableCredentialSuite for the credential type.
  ///
  /// Throws [SsiException] if no suite is available for the credential type.
  static VerifiableCredentialSuite getVcSuite(ParsedVerifiableCredential vc) {
    return switch (vc) {
      LdVcDataModelV1() => LdVcDm1Suite() as VerifiableCredentialSuite,
      LdVcDataModelV2() => LdVcDm2Suite() as VerifiableCredentialSuite,
      JwtVcDataModelV1() => JwtDm1Suite() as VerifiableCredentialSuite,
      SdJwtDataModelV2() => SdJwtDm2Suite() as VerifiableCredentialSuite,
      _ => throw SsiException(
          message: 'Suite for "${vc.runtimeType}" is not supported',
          code: SsiExceptionType.other.code,
        ),
    };
  }
}

RevocationList2020Status? getCredentialStatusFromVc(
    ParsedVerifiableCredential vc) {
  List<Map<String, dynamic>> credentialStatus;

  switch (vc) {
    case LdVcDataModelV1():
      final status = vc.credentialStatus;
      credentialStatus = status == null ? [] : [status.toJson()];
      break;
    case LdVcDataModelV2():
      credentialStatus =
          vc.credentialStatus.map((status) => status.toJson()).toList();
      break;
    case JwtVcDataModelV1():
      final status = vc.credentialStatus;
      credentialStatus = status == null ? [] : [status.toJson()];
      break;
    case SdJwtDataModelV2():
      credentialStatus =
          vc.credentialStatus.map((status) => status.toJson()).toList();
      break;
    default:
      return null;
  }

  for (final status in credentialStatus) {
    final type = status['type'];
    if (type == 'RevocationList2020Status') {
      final revocationStatus = RevocationList2020Status.fromJson(status);
      return revocationStatus;
    }
  }
  return null;
}
