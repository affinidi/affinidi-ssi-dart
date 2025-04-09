import '../credential_schema.dart';
import '../verifiable_credential.dart';

class ParsedVcDataModelV1 implements VerifiableCredential {
  ParsedVcDataModelV1(Map<String, dynamic> data)
      : _jsonDataModel = Map<String, dynamic>.unmodifiable(data),
        _rawData = Map<String, dynamic>.unmodifiable(data);

  final Map<String, dynamic> _jsonDataModel;

  final dynamic _rawData;

  @override
  dynamic get rawData => _rawData;

  @override
  DateTime? get validUntil {
    if (!_jsonDataModel.containsKey(VcDataModelV1Key.expirationDate.key)) {
      return null;
    }

    return DateTime.parse(
        _jsonDataModel[VcDataModelV1Key.expirationDate.key] as String);
  }

  @override
  String get issuer => _jsonDataModel[VcDataModelV1Key.issuer.key] as String;

  @override
  List<CredentialSchema> get credentialSchema {
    final data = _jsonDataModel[VcDataModelV1Key.credentialSchema.key];
    if (data == null) return [];

    if (data is List) {
      return data
          .map((schema) =>
              CredentialSchema.fromJson(schema as Map<String, dynamic>))
          .toList();
    }

    return [CredentialSchema.fromJson(data as Map<String, dynamic>)];
  }

  @override
  Map<String, dynamic> get credentialSubject =>
      _jsonDataModel[VcDataModelV1Key.credentialSubject.key]
          as Map<String, dynamic>;

  @override
  String get id => _jsonDataModel[VcDataModelV1Key.id.key] as String;

  @override
  DateTime get validFrom => DateTime.parse(
      _jsonDataModel[VcDataModelV1Key.issuanceDate.key] as String);

  @override
  List<String> get type =>
      List<String>.from(_jsonDataModel[VcDataModelV1Key.type.key] as List);

  @override
  Map<String, dynamic> toJson() => _jsonDataModel;

  @override
  // TODO: implement context
  List<String> get context => throw UnimplementedError();
}

enum VcDataModelV1Key {
  context(key: '@context'),
  proof,
  expirationDate,
  issuer,
  credentialSchema,
  credentialSubject,
  id,
  type,
  issuanceDate,
  ;

  final String? _key;

  String get key => _key ?? name;

  const VcDataModelV1Key({String? key}) : _key = key;
}
