abstract class JsonObject {
  JsonObject.fromJson(dynamic jsonData);
  Map<String, dynamic> toJson();
  @override
  String toString();
}
