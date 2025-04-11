import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../../../util/json_util.dart';
import '../credential_schema.dart';
import '../credential_status.dart';
import 'vc_data_model_v2_view.dart';

// TODO(cm) must implement adapter functions where needed to the generic VerifiableCredential
// TODO(cm) decide what to do with "holder"
// TODO(cm): add validation against the VCDM1 schema somewhere
// TODO(cm): must match fields in the spec https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
class VcDataModelV2 implements VcDataModelV2View {
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

  @override
  List<String> context;

  @override
  String? id;

  @override
  List<CredentialSchema> credentialSchema;

  @override
  CredentialStatus? credentialStatus;

  @override
  Map<String, dynamic> credentialSubject;

  @override
  String issuer;

  @override
  List<String> type;

  @override
  DateTime? validFrom;

  @override
  DateTime? validUntil;

  Map<String, dynamic> holder;

  @override
  Map<String, dynamic> proof;

  VcDataModelV2({
    required this.context,
    this.id,
    List<CredentialSchema>? credentialSchema,
    Map<String, dynamic>? credentialSubject,
    required this.issuer,
    required this.type,
    this.validFrom,
    this.validUntil,
    Map<String, String>? holder,
    Map<String, String>? proof,
    this.credentialStatus,
  })  : credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? {},
        holder = holder ?? {},
        proof = proof ?? {};

  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer;
    json[_P.type.key] = type;

    if (id != null) {
      json[_P.id.key] = id;
    }

    if (credentialSchema.isNotEmpty) {
      json[_P.credentialSchema.key] = _encodeCredentialSchema(credentialSchema);
    }

    final issDate = validFrom;
    if (issDate != null) {
      json[_P.validFrom.key] = issDate.toIso8601String();
    }

    final expDate = validUntil;
    if (expDate != null) {
      json[_P.validUntil.key] = expDate.toIso8601String();
    }

    if (credentialSubject.isNotEmpty) {
      json[_P.credentialSubject.key] = credentialSubject;
    }

    if (holder.isNotEmpty) {
      json[_P.holder.key] = holder;
    }

    if (proof.isNotEmpty) {
      json[_P.proof.key] = proof;
    }

    var credentialStatus = this.credentialStatus;
    if (credentialStatus != null) {
      json[_P.credentialStatus.key] = credentialStatus.toJson();
    }

    return json;
  }

  VcDataModelV2.fromJson(dynamic input)
      : context = [],
        credentialSchema = [],
        credentialSubject = {},
        holder = {},
        issuer = '',
        type = [],
        proof = {} {
    final json = jsonToMap(input);

    context = getStringList(json, _P.context.key, mandatory: true);
    id = getString(json, _P.id.key);
    issuer = getMandatoryString(json, _P.issuer.key);
    type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    );

    validFrom = getDateTime(json, _P.validFrom.key);
    validUntil = getDateTime(json, _P.validUntil.key);

    // FIXME handle arrays of subjects
    credentialSubject =
        Map.of(json[_P.credentialSubject.key] as Map<String, dynamic>);

    switch (json[_P.credentialSchema.key]) {
      case Map m:
        credentialSchema = [CredentialSchema.fromJson(jsonToMap(m))];

      case List l:
        credentialSchema = l
            .map((e) => CredentialSchema.fromJson(jsonToMap(e)))
            .toList(growable: true);

      case null:
        break;

      default:
        throw SsiException(
          message: 'invalid credentialSchema',
          code: SsiExceptionType.invalidJson.code,
        );
    }

    // FIXME handle simple string
    if (json.containsKey(_P.holder.key) && json[_P.holder.key] is Map) {
      holder = Map.of(json[_P.holder.key] as Map<String, dynamic>);
    }

    // FIXME use a typed object
    if (json.containsKey(_P.proof.key) && json[_P.proof.key] is Map) {
      proof = Map.of(json[_P.proof.key] as Map<String, dynamic>);
    }

    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = CredentialStatus.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }
  }

  dynamic _encodeCredentialSchema(
    List<CredentialSchema> credentialSchema,
  ) {
    if (credentialSchema.length == 1) {
      return credentialSchema.first.toJson();
    }

    return credentialSchema.fold(
      <Map<String, dynamic>>[],
      (list, cs) {
        list.add(cs.toJson());
        return list;
      },
    );
  }
}

/// Shortcut to make the code easier to read, p comes from property
typedef _P = VcDataModelV2Key;

enum VcDataModelV2Key {
  context(key: '@context'),
  proof,
  issuer,
  credentialSchema,
  credentialSubject,
  id,
  type,
  validFrom,
  validUntil,
  credentialStatus,
  holder,
  ;

  final String? _key;

  String get key => _key ?? name;

  const VcDataModelV2Key({String? key}) : _key = key;
}
