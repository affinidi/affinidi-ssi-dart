import 'dart:collection';

import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../field_types/context.dart';
import '../field_types/credential_schema.dart';
import '../field_types/credential_status/v1.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/holder.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v1.dart';
import '../field_types/terms_of_use.dart';
import '../verifiable_credential.dart';

part 'mutable_vc_data_model_v1.dart';

/// Represents a Verifiable Credential (VC) according to the W3C VC Data Model v1.1.
///
///  A Verifiable Credential (VC) is a digitally signed statement, issued by issuer
///
/// This class supports JSON serialization and deserialization for interoperability.
///  Example:
/// ```dart
/// VcDataModelV1(
///  context: [
///    'https://www.w3.org/2018/credentials/v1',
///    'https://schema.affinidi.com/UserProfileV1-0.jsonld'
///  ],
///  id: Uri.parse('uuid:123456abcd'),
///  type: {'VerifiableCredential', 'UserProfile'},
///  credentialSubject: [
///    CredentialSubject({
///      'Fname': 'Fname',
///      'Lname': 'Lame',
///      'Age': '22',
///      'Address': 'Eihhornstr'
///    })
///   ],
///  holder: Holder.uri('did:example:1'),
///  credentialSchema: [
///    CredentialSchema(
///        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
///        type: 'JsonSchemaValidator2018')
///  ],
///  issuanceDate: DateTime.now(),
///  issuer: Issuer.uri(signer.did),
///);
/// ```
class VcDataModelV1 implements VerifiableCredential {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  final JsonLdContext context;

  /// The optional identifier for the Verifiable Credential.
  @override
  final Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiableCredential'.
  @override
  final UnmodifiableSetView<String> type;

  /// The schema(s) used to define the structure of the credential.
  @override
  final Issuer issuer;

  /// The subject data contained in this credential.
  ///
  /// Example of a credential subject:
  /// ```
  /// {
  ///   "id": "did:example:123",
  ///   "name": "John Doe",
  /// }
  /// ```
  @override
  final UnmodifiableListView<CredentialSubject> credentialSubject;

  /// The cryptographic proof(s) created by the issuer.
  @override
  final UnmodifiableListView<EmbeddedProof> proof;

  /// The schema(s) used to define the structure of the credential.
  @override
  final UnmodifiableListView<CredentialSchema> credentialSchema;

  /// The date and time the credential was issued.
  final DateTime issuanceDate;

  /// The date and time the credential expires.
  final DateTime? expirationDate;

  /// The date and time the credential was issued.
  @override
  DateTime get validFrom => issuanceDate;

  /// The date and time the credential expires.
  @override
  DateTime? get validUntil => expirationDate;

  /// The identifier of the holder presenting the credentials.
  ///
  /// Typically a DID.
  final Holder? holder;

  /// Credential status object to validate credentials revocation
  final CredentialStatusV1? credentialStatus;

  /// service(s) for how the credential can be refreshed.
  final UnmodifiableListView<RefreshServiceV1> refreshService;

  /// The terms of use for the Verifiable Credential.
  @override
  final UnmodifiableListView<TermsOfUse> termsOfUse;

  /// Evidence supporting the claims in the credential.
  final UnmodifiableListView<Evidence> evidence;

  /// Converts the [VcDataModelV1] instance to a JSON representation.
  ///
  /// Returns a [Map<String, dynamic>] representing the JSON structure of the credential.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context.toJson();
    json[_P.issuer.key] = issuer.toJson();
    json[_P.type.key] = type.toList();
    json[_P.id.key] = id?.toString();
    json[_P.credentialSchema.key] = encodeListToSingleOrArray(credentialSchema);
    json[_P.holder.key] = holder?.toJson();
    json[_P.issuanceDate.key] = issuanceDate.toIso8601String();
    json[_P.expirationDate.key] = expirationDate?.toIso8601String();
    json[_P.credentialSubject.key] =
        encodeListToSingleOrArray(credentialSubject);
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.credentialStatus.key] = credentialStatus?.toJson();
    json[_P.refreshService.key] = encodeListToSingleOrArray(refreshService);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.evidence.key] = encodeListToSingleOrArray(evidence);

    return cleanEmpty(json);
  }

  /// Validates the essential Verifiable Credential properties (`context`, `type`, `credentialSubject`).
  ///
  /// Ensures [context] is not empty and starts with [dmV1ContextUrl],
  /// and the [type] is not empty.
  /// and the [credentialSubject] is not empty
  ///
  /// Throws [SsiException] if validation fails. Returns `true` if valid.
  bool validate() {
    if (context.uris.isEmpty && context.terms.isEmpty) {
      throw SsiException(
        message: '`${_P.context.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (context.uris.first.toString() != dmV1ContextUrl) {
      throw SsiException(
        message:
            'The first URI of `${_P.context.key}` property should always be $dmV1ContextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (type.isEmpty) {
      throw SsiException(
        message: '`${_P.type.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (credentialSubject.isEmpty) {
      throw SsiException(
        message: '`${_P.credentialSubject.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return true;
  }

  /// Creates a [VcDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [id] is otptionla identifier (optional)
  /// the [credentialSubject] is contain claims of subject (required)
  /// The [issuer] is issuer of this VC (required)
  /// The [type] is an array that must include 'VerifiableCredential' (required)
  /// The [issuanceDate] is date and time at this VC is issued (required)
  /// The [credentialSchema] is credential schema against VC is issued (optional)
  /// The [expirationDate] is expiry date of VC (optional)
  /// The [holder] is an identifier for the holder (optional)
  /// The [proof] is a cryptographic proof (optional)
  /// The [credentialStatus] is a list of Credential Status object (optional)
  /// The [refreshService] is a list of refresh service (optional)
  /// The [termsOfUse] is a list of terms of use (optional)
  /// The [evidence] is a list of evidence (optional)
  VcDataModelV1({
    required this.context,
    this.id,
    required List<CredentialSubject> credentialSubject,
    required this.issuer,
    required Set<String> type,
    required this.issuanceDate,
    List<CredentialSchema>? credentialSchema,
    this.expirationDate,
    this.holder,
    List<EmbeddedProof>? proof,
    this.credentialStatus,
    List<RefreshServiceV1>? refreshService,
    List<TermsOfUse>? termsOfUse,
    List<Evidence>? evidence,
  })  : credentialSubject = UnmodifiableListView(credentialSubject),
        type = UnmodifiableSetView(type),
        proof = UnmodifiableListView(proof ?? []),
        credentialSchema = UnmodifiableListView(credentialSchema ?? []),
        refreshService = UnmodifiableListView(refreshService ?? []),
        termsOfUse = UnmodifiableListView(termsOfUse ?? []),
        evidence = UnmodifiableListView(evidence ?? []) {
    validate();
  }

  /// Creates a [VcDataModelV1] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory VcDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = JsonLdContext.fromJson(json[_P.context.key]);

    final id = getUri(json, _P.id.key);
    final type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    ).toSet();

    final issuer = Issuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<CredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) => CredentialSubject.fromJson(item as Map<String, dynamic>),
        mandatory: true,
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<CredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) => CredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final issuanceDate =
        getDateTime(json, _P.issuanceDate.key, mandatory: true)!;

    final expirationDate = getDateTime(json, _P.expirationDate.key);

    Holder? holder;
    if (json.containsKey(_P.holder.key)) {
      holder = Holder.fromJson(json[_P.holder.key]);
    }

    CredentialStatusV1? credentialStatus;
    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = CredentialStatusV1.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }

    final refreshService = parseListOrSingleItem<RefreshServiceV1>(
        json,
        _P.refreshService.key,
        (item) => RefreshServiceV1.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<TermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => TermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<Evidence>(json, _P.evidence.key,
        (item) => Evidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return VcDataModelV1(
        context: context,
        id: id,
        credentialSubject: credentialSubject,
        issuer: issuer,
        type: type,
        issuanceDate: issuanceDate,
        credentialSchema: credentialSchema,
        expirationDate: expirationDate,
        holder: holder,
        proof: proof,
        credentialStatus: credentialStatus,
        refreshService: refreshService,
        termsOfUse: termsOfUse,
        evidence: evidence);
  }

  /// Creates a new [VcDataModelV1] instance as a deep copy of the provided [input].
  ///
  /// This constructor initializes a new object with the same values as the
  /// properties of the [input] `VcDataModelV1` instance.
  VcDataModelV1.clone(VcDataModelV1 input)
      : this(
            context: input.context,
            id: input.id,
            credentialSubject: input.credentialSubject,
            issuer: input.issuer,
            type: input.type,
            issuanceDate: input.issuanceDate,
            credentialSchema: input.credentialSchema,
            expirationDate: input.expirationDate,
            holder: input.holder,
            proof: input.proof,
            credentialStatus: input.credentialStatus,
            refreshService: input.refreshService,
            termsOfUse: input.termsOfUse,
            evidence: input.evidence);

  /// Factory constructor to create a [VcDataModelV1] instance from a mutable [MutableVcDataModelV1]
  ///
  /// Example:
  /// ```dart
  /// MutableVcDataModelV1 mutableData = MutableVcDataModelV1(
  ///   id: 'some-unique-id',
  ///   type: ['VerifiableCredential', 'ExampleCredential'],
  ///   issuer: 'did:example:issuer',
  ///   issuanceDate: DateTime.now(),
  ///   credentialSubject: {'name': 'John Doe'},
  /// );
  ///
  /// VcDataModelV1 immutableData = VcDataModelV1.fromMutable(mutableData);
  /// ```
  factory VcDataModelV1.fromMutable(MutableVcDataModelV1 data) =>
      VcDataModelV1.fromJson(data.toJson());
}
