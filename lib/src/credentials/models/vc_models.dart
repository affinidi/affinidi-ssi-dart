class RefreshService {
  final String? id;
  final String? type;

  RefreshService({
    this.id,
    this.type,
  });

  factory RefreshService.fromJson(Map<String, dynamic> json) => RefreshService(
        id: json['id'] as String?,
        type: json['type'] as String?,
      );

  Map<String, dynamic> toJson() => {
        if (id != null) 'id': id,
        if (type != null) 'type': type,
      };
}

class TermOfUse {
  final String? id;
  final String? type;

  TermOfUse({
    this.id,
    this.type,
  });

  factory TermOfUse.fromJson(Map<String, dynamic> json) => TermOfUse(
        id: json['id'] as String?,
        type: json['type'] as String?,
      );

  Map<String, dynamic> toJson() => {
        if (id != null) 'id': id,
        if (type != null) 'type': type,
      };
}

class Evidence {
  final String? id;
  final String? type;

  Evidence({
    this.id,
    this.type,
  });

  factory Evidence.fromJson(Map<String, dynamic> json) => Evidence(
        id: json['id'] as String?,
        type: json['type'] as String?,
      );

  Map<String, dynamic> toJson() => {
        if (id != null) 'id': id,
        if (type != null) 'type': type,
      };
}
