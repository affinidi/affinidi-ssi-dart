import 'dart:convert';

import 'package:ssi/src/credentials/models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';

class LdVcDataModelV2 extends VcDataModelV2
    implements ParsedVerifiableCredential<String, VcDataModelV2> {
  String? _serialized;

  LdVcDataModelV2({
    required super.context,
    required super.id,
    super.credentialSchema,
    super.credentialSubject,
    required super.issuer,
    required super.type,
    super.validFrom,
    super.validUntil,
    super.holder,
    super.proof,
    super.credentialStatus,
    required serialized,
  }) : _serialized = serialized;

  LdVcDataModelV2.fromJson(super.input)
      : _serialized = input['serialized'],
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    _serialized ??= jsonEncode(toJson());
    return _serialized!;
  }
}
