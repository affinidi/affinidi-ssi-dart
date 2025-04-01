/// To be not be exposed from common package
enum SsiExceptionType {
  /// The Verifiable Credential Object Data Model is not supported
  unableToParseVerifiableCredential(code: 'unable_to_parse'),

  /// An error occurred while trying to resolve a did
  unableToResolveDid(code: 'unable_to_resolve_did'),

  /// The DID Document is not valid
  invalidDidDocument(code: 'invalid_did_document'),

  /// The did:peer or document is invalid
  invalidDidPeer(code: 'invalid_did_peer'),

  /// The did:web or document is invalid
  invalidDidWeb(code: 'invalid_did_web'),

  /// The did:key is invalid
  invalidDidKey(code: 'invalid_did_key'),

  /// An unknown error has occurred.
  other(code: 'other'),
  ;

  const SsiExceptionType({required this.code});

  final String code;
}
