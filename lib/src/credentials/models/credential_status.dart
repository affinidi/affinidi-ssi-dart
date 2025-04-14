/// Provides information about the current status of a verifiable credential.
///
/// The credentialStatus enables discovery of information about whether
/// a credential is suspended, revoked, or still valid.
class CredentialStatus {
  /// The URL identifier for this status information.
  final Uri? id;

  /// The type of status mechanism used.
  final String type;

  /// Creates a [CredentialStatus] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  CredentialStatus({
    this.id,
    required this.type,
  });

  /// Creates a [CredentialStatus] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory CredentialStatus.fromJson(Map<String, dynamic> json) {
    final id = json['id'] != null ? Uri.parse(json['id'] as String) : null;
    final type = json['type'] as String;

    return CredentialStatus(id: id, type: type);
  }

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() {
    final json = {
      'type': type,
    };

    if (id != null) {
      json['id'] = id.toString();
    }

    return json;
  }
}
