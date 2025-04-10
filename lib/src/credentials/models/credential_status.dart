/// credentialStatus enables discovery of information about the current status
/// of a verifiable credential, such as whether it is suspended or revoked.
class CredentialStatus {
  /// Returns the URL of the schema including domain and filename
  final Uri? id;

  /// Returns stauts type
  final String type;

  /// Creates a [CredentialStatus] instance.
  ///
  /// [id] - Base URL where the schema is hosted
  /// [type] - Name of the schema without extension
  CredentialStatus({
    this.id,
    required this.type,
  });

  /// Creates a [CredentialStatus] from JSON data
  ///
  /// [json] must contain a 'type' field
  factory CredentialStatus.fromJson(Map<String, dynamic> json) {
    final id = json['id'] != null ? Uri.parse(json['id']) : null;
    final type = json['type'] as String;

    return CredentialStatus(id: id, type: type);
  }

  /// Converts the [CredentialStatus] to JSON format
  ///
  /// Returns a map containing 'id' and 'type' fields
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
