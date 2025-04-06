import 'dart:convert';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

/// Converts [input] to a `Map<String, dynamic>`
Map<String, dynamic> jsonToMap(dynamic input) {
  if (input is String) {
    return jsonDecode(input);
  } else if (input is Map<String, dynamic>) {
    return input;
  } else if (input is Map<dynamic, dynamic>) {
    return input.map((key, value) {
      if (key is! String) {
        throw SsiException(
          message:
              'jsonToMap: unsupported datatype ${key.runtimeType} for `$key`, keys must be String,',
          code: SsiExceptionType.invalidJson.code,
        );
      }
      return MapEntry(key, value);
    });
  } else {
    throw SsiException(
      message:
          'jsonToMap: unknown datatype ${input.runtimeType} for `$input`. Only String or Map<String, dynamic> accepted',
      code: SsiExceptionType.invalidJson.code,
    );
  }
}

/// Return [fieldName] as `String`, or null. Throws an exception if the field
/// value is not a string.
String? getString(Map<String, dynamic> json, String fieldName) {
  if (json.containsKey(fieldName) && json[fieldName] is! String) {
    throw SsiException(
      message: '`$fieldName` must be a string',
      code: SsiExceptionType.invalidJson.code,
    );
  }
  return json[fieldName];
}

/// Return [fieldName] as `String`.Throws an exception if the field
/// value is not a string or the field does not exist.
String getMandatoryString(Map<String, dynamic> json, String fieldName) {
  if (!json.containsKey(fieldName) || json[fieldName] is! String) {
    throw SsiException(
      message: '`$fieldName` property is mandatory',
      code: SsiExceptionType.invalidJson.code,
    );
  }
  return json[fieldName];
}

/// Return [fieldName] as `List<String>`, or throw an exception
List<String> getMandatoryStringList(
  Map<String, dynamic> json,
  String fieldName, {
  bool allowSingleValue = false,
}) {
  if (!json.containsKey(fieldName)) {
    throw SsiException(
      message: '`$fieldName` property is mandatory',
      code: SsiExceptionType.invalidJson.code,
    );
  }

  final jsonValue = json[fieldName];
  switch (jsonValue) {
    case String s:
      if (!allowSingleValue) {
        throw SsiException(
          message: '`$fieldName` must be a list',
          code: SsiExceptionType.invalidJson.code,
        );
      }
      return [s];

    case List l:
      return l.map((e) => e as String).toList(growable: true);

    default:
      throw SsiException(
        message: '`$fieldName` must be a list or an individual string',
        code: SsiExceptionType.invalidJson.code,
      );
  }
}

DateTime? getDateTime(
  Map<String, dynamic> json,
  String fieldName, {
  bool mandatory = false,
}) {
  var fieldExists = json.containsKey(fieldName);

  if (!fieldExists && !mandatory) {
    return null;
  }

  if (!fieldExists && mandatory) {
    throw SsiException(
      message: '`$fieldName` property is mandatory',
      code: SsiExceptionType.invalidJson.code,
    );
  }

  final jsonValue = json[fieldName];
  switch (jsonValue) {
    case String s:
      return DateTime.parse(s);

    default:
      throw SsiException(
        message: '`$fieldName` must be a valid date time',
        code: SsiExceptionType.invalidJson.code,
      );
  }
}

// /// Return [fieldName] as `List<String>`, or throw an exception
// List<ObjectWithId> getObjectWithIdList(
//   Map<String, dynamic> json,
//   String fieldName, {
//   bool allowSingleValue = false,
//   bool mandatory = false,
// }) {
//   var fieldExists = json.containsKey(fieldName);
//
//   if (!fieldExists && !mandatory) {
//     return [];
//   }
//
//   if (!fieldExists && mandatory) {
//     throw SsiException(
//       message: '`$fieldName` property is mandatory',
//       code: SsiExceptionType.invalidJson.code,
//     );
//   }
//
//   final jsonValue = json[fieldName];
//   switch (jsonValue) {
//     case Map o:
//       if (!allowSingleValue) {
//         throw SsiException(
//           message: '`$fieldName` must be a Map',
//           code: SsiExceptionType.invalidJson.code,
//         );
//       }
//       return [ObjectWithId.fromJson(o)];
//
//     case List l:
//       return l.map(ObjectWithId.fromJson).toList(growable: true);
//
//     default:
//       throw SsiException(
//         message: '`$fieldName` must be a list or an individual object with id',
//         code: SsiExceptionType.invalidJson.code,
//       );
//   }
// }
//
// class ObjectWithId {
//   String? id;
//   Map<String, dynamic> otherFields;
//
//   ObjectWithId({
//     this.id,
//     Map<String, dynamic>? otherFields,
//   }) : otherFields = otherFields ?? {};
//
//   ObjectWithId.fromJson(dynamic input)
//       : id = "",
//         otherFields = {} {
//     final json = jsonToMap(input);
//
//     id = getString(json, 'id');
//
//     otherFields = Map.from(json);
//     otherFields.remove('id');
//   }
//
//   Map<String, dynamic> toJson() {
//     Map<String, dynamic> json = Map.from(otherFields);
//     if (id != null) {
//       json['id'] = id;
//     }
//     return json;
//   }
// }
