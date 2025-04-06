import '../credential_schema.dart';
import '../verifiable_credential.dart';

// TODO must implement VcDataModelV20 (which is not yet fully defined)
class ParsedVcDataModelV20 implements VerifiableCredential {
  ParsedVcDataModelV20(Map<String, dynamic> data)
      : _jsonDataModel = Map<String, dynamic>.unmodifiable(data),
        _rawData = Map<String, dynamic>.unmodifiable(data);

  final Map<String, dynamic> _jsonDataModel;

  final dynamic _rawData;

  @override
  dynamic get rawData => _rawData;

  @override
  List<CredentialSchema> get credentialSchema {
    final data = _jsonDataModel[VcDataModelV20Key.credentialSchema.key];
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
      _jsonDataModel[VcDataModelV20Key.credentialSubject.key]
          as Map<String, dynamic>;

  @override
  String get id => _jsonDataModel[VcDataModelV20Key.id.key] as String;

  @override
  DateTime get validFrom =>
      DateTime.parse(_jsonDataModel[VcDataModelV20Key.validFrom.key] as String);

  @override
  String get issuer => _jsonDataModel[VcDataModelV20Key.issuer.key] as String;

  @override
  dynamic toJson() => _jsonDataModel;

  @override
  List<String> get type =>
      List<String>.from(_jsonDataModel[VcDataModelV20Key.type.key] as List);

  @override
  DateTime? get validUntil {
    if (!_jsonDataModel.containsKey(VcDataModelV20Key.validUntil.key)) {
      return null;
    }

    return DateTime.parse(
        _jsonDataModel[VcDataModelV20Key.validUntil.key] as String);
  }

  @override
  // TODO: implement context
  List<String> get context => throw UnimplementedError();
}

enum VcDataModelV20Key {
  context(key: '@context'),
  proof,
  id,
  credentialSchema,
  credentialSubject,
  issuer,
  type,
  validFrom,
  validUntil,
  ;

  final String? _key;

  String get key => _key ?? name;

  const VcDataModelV20Key({String? key}) : _key = key;
}
