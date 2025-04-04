import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/models/vc_data_model_v2_key.dart';

import '../../../../ssi.dart';

class ParsedVcDataModelV2 extends VcDataModelV2 {
  ParsedVcDataModelV2(Map<String, dynamic> data)
      : _jsonDataModel = Map<String, dynamic>.unmodifiable(data),
        _rawData = Map<String, dynamic>.unmodifiable(data);

  final Map<String, dynamic> _jsonDataModel;

  final Map<String, dynamic> _rawData;

  @override
  Map<String, dynamic> get rawData => _rawData;

  @override
  List<CredentialSchema> get credentialSchema {
    final data = _jsonDataModel[VcDataModelV2Key.credentialSchema.key];
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
      _jsonDataModel[VcDataModelV2Key.credentialSubject.key]
          as Map<String, dynamic>;

  @override
  String get id => _jsonDataModel[VcDataModelV2Key.id.key] as String;

  @override
  DateTime get validFrom =>
      DateTime.parse(_jsonDataModel[VcDataModelV2Key.validFrom.key] as String);

  @override
  String get issuer => _jsonDataModel[VcDataModelV2Key.issuer.key] as String;

  @override
  Map<String, dynamic> toJson() => _jsonDataModel;

  @override
  List<String> get type =>
      List<String>.from(_jsonDataModel[VcDataModelV2Key.type.key] as List);

  @override
  DateTime? get validUntil {
    if (!_jsonDataModel.containsKey(VcDataModelV2Key.validUntil.key)) {
      return null;
    }

    return DateTime.parse(
        _jsonDataModel[VcDataModelV2Key.validUntil.key] as String);
  }

  @override
  // TODO: implement context
  List<String> get context => throw UnimplementedError();
}
