// Enum for restricted claim names in SD-JWT.
///
/// These claim names are reserved and should not be overridden.
/// - **_sd**: Indicates selectively disclosable claims.
/// - **_sd_alg**: Specifies the used algorithm.
/// - **cnf**: Confirmation claims.
enum IssuerJwtRestrictedNames {
  /// The set of restricted claim names for SD-JWT.
  ///
  /// Contains the following restricted names:
  /// - '...' (ellipsis)
  /// - '_sd' (selectively disclosable claims)
  /// - '_sd_alg' (hashing algorithm)
  /// - 'cnf' (confirmation claims)
  sdJwt(<String>{'...', '_sd', '_sd_alg', 'cnf'});

  final Set<String> _restrictedClaimNames;

  const IssuerJwtRestrictedNames(this._restrictedClaimNames);

  /// Checks if a given claim name is restricted.
  bool isNameRestricted(String name) {
    return _restrictedClaimNames.contains(name);
  }
}
