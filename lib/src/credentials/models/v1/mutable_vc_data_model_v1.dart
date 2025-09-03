part of 'vc_data_model_v1.dart';

/// Default VC Data Model v1.1 context url
const String dmV1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

/// Represents a Verifiable Credential (VC) according to the W3C VC Data Model v1.1.
///
///  A Verifiable Credential (VC) is a digitally signed statement, issued by issuer
///
/// This class supports JSON serialization and deserialization for interoperability.
///  Example:
/// ```dart
/// MutableVcDataModelV1(
///  context: [
///    'https://www.w3.org/2018/credentials/v1',
///    'https://schema.affinidi.com/UserProfileV1-0.jsonld'
///  ],
///  id: Uri.parse('uuid:123456abcd'),
///  type: {'VerifiableCredential', 'UserProfile'},
///  credentialSubject: [
///    MutableCredentialSubject({
///      'Fname': 'Fname',
///      'Lname': 'Lame',
///      'Age': '22',
///      'Address': 'Eihhornstr'
///    })
///   ],
///  holder: MutableHolder.uri('did:example:1'),
///  credentialSchema: [
///    MutableCredentialSchema(
///        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
///        type: 'JsonSchemaValidator2018')
///  ],
///  issuanceDate: DateTime.now(),
///  issuer: Issuer.uri(signer.did),
///);
/// ```
class MutableVcDataModelV1 {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  List<dynamic> context;

  /// The optional identifier for the Verifiable Credential.
  Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiableCredential'.
  Set<String> type;

  /// The schema(s) used to define the structure of the credential.
  List<MutableCredentialSchema> credentialSchema;

  /// The subject data contained in this credential.
  ///
  /// Example of a credential subject:
  /// ```
  /// {
  ///   "id": "did:example:123",
  ///   "name": "John Doe",
  /// }
  /// ```
  List<MutableCredentialSubject> credentialSubject;

  /// The entity that issued this credential.
  ///
  /// Typically a DID.
  MutableIssuer? issuer;

  /// The date and time at which the credential was issued
  DateTime? issuanceDate;

  /// The date and time at which the credential becomes invalid.
  DateTime? expirationDate;

  /// The identifier of the holder presenting the credentials.
  ///
  /// Typically a DID.
  MutableHolder? holder;

  /// The cryptographic proof(s) created by the issuer.
  List<EmbeddedProof> proof;

  /// Credential status object to validate credentials revocation
  MutableCredentialStatusV1? credentialStatus;

  /// service(s) for how the credential can be refreshed.
  List<MutableRefreshServiceV1> refreshService;

  /// The terms of use for the Verifiable Credential.
  List<MutableTermsOfUse> termsOfUse;

  /// Evidence supporting the claims in the credential.
  List<MutableEvidence> evidence;

  /// Converts the [MutableVcDataModelV1] instance to a JSON representation.
  ///
  /// Returns a [Map<String, dynamic>] representing the JSON structure of the credential.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer?.toJson();
    json[_P.type.key] = type.toList();
    json[_P.id.key] = id?.toString();
    json[_P.credentialSchema.key] = encodeListToSingleOrArray(credentialSchema);
    json[_P.holder.key] = holder?.toJson();
    json[_P.issuanceDate.key] = issuanceDate?.toIso8601String();
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

  /// Creates a [MutableVcDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [id] is otptionla identifier (optional)
  /// The [credentialSchema] is credential schema against VC is issued (optional)
  /// the [credentialSubject] is contain claims of subject (required)
  /// The [issuer] is issuer of this VC (required)
  /// The [type] is an array that must include 'VerifiableCredential' (required)
  /// The [issuanceDate] is date and time at this VC is issued (required)
  /// The [expirationDate] is expiry date of VC (optional)
  /// The [holder] is an identifier for the holder (optional)
  /// The [proof] is a cryptographic proof (optional)
  /// The [credentialStatus] is a list of Credential Status object (optional)
  /// The [refreshService] is a list of refresh service (optional)
  /// The [termsOfUse] is a list of terms of use (optional)
  /// The [evidence] is a list of evidence (optional)
  MutableVcDataModelV1({
    List<dynamic>? context,
    this.id,
    List<MutableCredentialSchema>? credentialSchema,
    List<MutableCredentialSubject>? credentialSubject,
    this.issuer,
    Set<String>? type,
    this.issuanceDate,
    this.expirationDate,
    this.holder,
    List<EmbeddedProof>? proof,
    this.credentialStatus,
    List<MutableRefreshServiceV1>? refreshService,
    List<MutableTermsOfUse>? termsOfUse,
    List<MutableEvidence>? evidence,
  })  : context = context ?? [],
        credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? [],
        type = type ?? {},
        proof = proof ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];

  /// Constructs a [MutableVcDataModelV1] instance from a JSON object.
  ///
  /// The [input] parameter is a dynamic type
  /// representing the JSON structure of the Verifiable Credential.  This factory
  /// constructor parses the JSON and populates the properties of the
  /// [MutableVcDataModelV1] instance.
  factory MutableVcDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getContextList(json, _P.context.key, mandatory: true);
    final id = getUri(json, _P.id.key);
    final type =
        getStringList(json, _P.type.key, allowSingleValue: true).toSet();

    final issuer = MutableIssuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<MutableCredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) =>
            MutableCredentialSubject.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<MutableCredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) =>
            MutableCredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final issuanceDate = getDateTime(json, _P.issuanceDate.key);
    final expirationDate = getDateTime(json, _P.expirationDate.key);

    final holder = MutableHolder.fromJson(json[_P.holder.key]);

    MutableCredentialStatusV1? credentialStatus;
    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = MutableCredentialStatusV1.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }

    final refreshService = parseListOrSingleItem<MutableRefreshServiceV1>(
        json,
        _P.refreshService.key,
        (item) =>
            MutableRefreshServiceV1.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<MutableTermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => MutableTermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<MutableEvidence>(
        json,
        _P.evidence.key,
        (item) => MutableEvidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return MutableVcDataModelV1(
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
}

typedef _P = VcDataModelV1Key;

/// Defines the keys used in the [MutableVcDataModelV1] class.
///
/// Each value represents a key that might be used in the JSON representation
/// of a Verifiable Credential.
enum VcDataModelV1Key {
  /// Key for the `@context` property, representing the JSON-LD context.
  context(key: '@context'),

  /// Key for the `proof` property, representing cryptographic proofs.
  proof,

  /// Key for the `expirationDate` property, representing the expiration date.
  expirationDate,

  /// Key for the `issuer` property, representing the issuer of the credential.
  issuer,

  /// Key for the `credentialSchema` property, representing the schema.
  credentialSchema,

  /// Key for the `credentialSubject` property, representing the subject.
  credentialSubject,

  /// Key for the `id` property, representing the unique identifier.
  id,

  /// Key for the `type` property, representing the credential type.
  type,

  /// Key for the `issuanceDate` property, representing the issuance date.
  issuanceDate,

  /// Key for the `credentialStatus` property, representing the credential status.
  credentialStatus,

  /// Key for the `holder` property, representing the holder of the credential.
  holder,

  /// Key for the `refreshService` property, representing the refresh service.
  refreshService,

  /// Key for the `termsOfUse` property, representing the terms of use.
  termsOfUse,

  /// Key for the `evidence` property, representing the evidence.
  evidence,
  ;

  final String? _key;

  /// Returns the key string (custom or enum name).
  String get key => _key ?? name;

  const VcDataModelV1Key({String? key}) : _key = key;
}
