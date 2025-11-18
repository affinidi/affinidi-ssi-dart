import '../../../ssi.dart';

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
    return getVcSuiteWithDocumentLoader(vc, null);
  }

  /// Returns the appropriate suite for the given credential with a custom document loader.
  ///
  /// [vc] - The parsed verifiable credential to find a suite for.
  /// [customDocumentLoader] - Optional custom document loader for loading external resources.
  ///
  /// Returns the matching VerifiableCredentialSuite for the credential type.
  ///
  /// Throws [SsiException] if no suite is available for the credential type.
  ///
  /// Deprecated: Use [getVcSuiteWithOptions] instead for more configuration options.
  @Deprecated(
      'Use getVcSuiteWithOptions instead for more configuration options')
  static VerifiableCredentialSuite getVcSuiteWithDocumentLoader(
    ParsedVerifiableCredential vc,
    DocumentLoader? customDocumentLoader,
  ) {
    return getVcSuiteWithOptions(
      vc,
      customDocumentLoader: customDocumentLoader,
    );
  }

  /// Returns the appropriate suite for the given credential with custom configuration.
  ///
  /// [vc] - The parsed verifiable credential to find a suite for.
  /// [customDocumentLoader] - Optional custom document loader for loading external resources.
  /// [didResolver] - Optional custom DID resolver for resolving DID documents.
  ///
  /// Returns the matching VerifiableCredentialSuite for the credential type.
  ///
  /// Throws [SsiException] if no suite is available for the credential type.
  static VerifiableCredentialSuite getVcSuiteWithOptions(
    ParsedVerifiableCredential vc, {
    DocumentLoader? customDocumentLoader,
    DidResolver? didResolver,
  }) {
    return switch (vc) {
      LdVcDataModelV1() => LdVcDm1Suite(
          customDocumentLoader: customDocumentLoader,
        ) as VerifiableCredentialSuite,
      LdVcDataModelV2() => LdVcDm2Suite(
          customDocumentLoader: customDocumentLoader,
        ) as VerifiableCredentialSuite,
      JwtVcDataModelV1() => JwtDm1Suite() as VerifiableCredentialSuite,
      SdJwtDataModelV2() => SdJwtDm2Suite() as VerifiableCredentialSuite,
      _ => throw SsiException(
          message: 'Suite for "${vc.runtimeType}" is not supported',
          code: SsiExceptionType.other.code,
        ),
    };
  }
}
