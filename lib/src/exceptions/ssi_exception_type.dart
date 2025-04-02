/// To be not be exposed from common package
enum SsiExceptionType {
  /// The Verifiable Credential Object Data Model is not supported
  unableToParseVerifiableCredential(code: 'unable_to_parse'),
  /// KeyPair missing private key
  keyPairMissingPrivateKey(code: 'key_pair_missing_private_key'),

  /// An unknown error has occurred.
  other(code: 'other'),
  ;

  const SsiExceptionType({required this.code});

  final String code;
}
