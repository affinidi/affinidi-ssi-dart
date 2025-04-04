import 'credential_schema.dart';
import 'verifiable_credential.dart';

class ParsedVcDataModelV11 implements VerifiableCredential {
  ParsedVcDataModelV11(Map<String, dynamic> data)
      : _jsonDataModel = Map<String, dynamic>.unmodifiable(data),
        _rawData = Map<String, dynamic>.unmodifiable(data);

  final Map<String, dynamic> _jsonDataModel;

  final dynamic _rawData;

  @override
  dynamic get rawData => _rawData;

  @override
  DateTime? get validUntil {
    if (!_jsonDataModel.containsKey(VcDataModelV11Key.expirationDate.key)) {
      return null;
    }

    return DateTime.parse(
        _jsonDataModel[VcDataModelV11Key.expirationDate.key] as String);
  }

  @override
  String get issuer => _jsonDataModel[VcDataModelV11Key.issuer.key] as String;

  @override
  List<CredentialSchema> get credentialSchema {
    final data = _jsonDataModel[VcDataModelV11Key.credentialSchema.key];
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
      _jsonDataModel[VcDataModelV11Key.credentialSubject.key]
          as Map<String, dynamic>;

  @override
  String get id => _jsonDataModel[VcDataModelV11Key.id.key] as String;

  @override
  DateTime get validFrom => DateTime.parse(
      _jsonDataModel[VcDataModelV11Key.issuanceDate.key] as String);

  @override
  List<String> get type =>
      List<String>.from(_jsonDataModel[VcDataModelV11Key.type.key] as List);

  @override
  dynamic toJson() => _jsonDataModel;

  @override
  // TODO: implement context
  List<String> get context => throw UnimplementedError();
}

enum VcDataModelV11Key {
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

  const VcDataModelV11Key({String? key}) : _key = key;
}
