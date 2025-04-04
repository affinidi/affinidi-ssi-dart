
enum VcDataModelV2Key {
  context(key: '@context'),
  proof,
  id,
  credentialSchema,
  credentialSubject,
  issuer,
  type,
  validFrom,
  validUntil
  ;

  final String? _key;

  String get key => _key ?? name;

  const VcDataModelV2Key({String? key}) : _key = key;
}