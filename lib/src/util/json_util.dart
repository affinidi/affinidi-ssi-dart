import 'dart:convert';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

/// Converts [input] to a `Map<String, dynamic>`
Map<String, dynamic> jsonToMap(dynamic input) {
  if (input is String) {
    return jsonDecode(input) as Map<String, dynamic>;
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
  return json[fieldName] as String?;
}

/// Return [fieldName] as `String`. Throws an exception if the field
/// value is not a string or the field does not exist.
String getMandatoryString(Map<String, dynamic> json, String fieldName) {
  if (!json.containsKey(fieldName) || json[fieldName] is! String) {
    throw SsiException(
      message: '`$fieldName` property is mandatory',
      code: SsiExceptionType.invalidJson.code,
    );
  }
  return json[fieldName] as String;
}

/// Return [fieldName] as `List<String>`
List<String> getStringList(
  Map<String, dynamic> json,
  String fieldName, {
  bool allowSingleValue = false,
  bool mandatory = false,
}) {
  final fieldExists = json.containsKey(fieldName);

  if (!fieldExists && !mandatory) {
    return [];
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
      if (!allowSingleValue) {
        throw SsiException(
          message: '`$fieldName` must be a list',
          code: SsiExceptionType.invalidJson.code,
        );
      }
      return [s];

    case List l:
      if (l.isEmpty) {
        throw SsiException(
          message: '`$fieldName` property must have at least one value',
          code: SsiExceptionType.invalidJson.code,
        );
      }
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
  final fieldExists = json.containsKey(fieldName);

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

/// Return [fieldName] as `String`, or null. Throws an exception if the field
/// value is not a string.
Uri? getUri(Map<String, dynamic> json, String fieldName) {
  if (json.containsKey(fieldName) &&
      (json[fieldName] is! String && json[fieldName] is! Uri)) {
    throw SsiException(
      message: '`$fieldName` must be a string or uri',
      code: SsiExceptionType.invalidJson.code,
    );
  }

  final val = json[fieldName];

  return val == null
      ? null
      : val is Uri
          ? val
          : Uri.parse(val as String);
}

/// Return [fieldName] as `String`. Throws an exception if the field
/// value is not a string or the field does not exist.
Uri getMandatoryUri(Map<String, dynamic> json, String fieldName) {
  if (!json.containsKey(fieldName)) {
    throw SsiException(
      message: '`$fieldName` property is mandatory',
      code: SsiExceptionType.invalidJson.code,
    );
  }

  return getUri(json, fieldName)!;
}

/// Add an optional field to [json] if [fieldValue] is not null
void addOptional(
  Map<String, dynamic> json,
  String fieldName,
  dynamic fieldValue,
) {
  if (fieldValue != null) {
    json[fieldName] = fieldValue;
  }
}

void addList<E>(
  Map<String, dynamic> json,
  String fieldName,
  List<E> list, {
  bool mandatory = false,
  bool allowSingleValue = false,
}) {
  if (list.isEmpty && !mandatory) {
    return;
  }

  if (list.isEmpty && mandatory) {
    throw SsiException(
      message: '`$fieldName` must not be empty',
      code: SsiExceptionType.invalidJson.code,
    );
  }

  if (list.length == 1 && allowSingleValue) {
    json[fieldName] = list.first;
  } else {
    json[fieldName] = list;
  }
}

List<T> parseListOrSingleItem<T>(
  dynamic json,
  String fieldName,
  T Function(dynamic) parser, {
  bool allowSingleValue = false,
  bool mandatory = false,
}) {
  final jsonValue = json[fieldName];

  if (jsonValue == null) {
    if (mandatory) {
      throw SsiException(
        message: '`$fieldName` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return [];
  }

  if (jsonValue is List) {
    if (jsonValue.isEmpty && mandatory) {
      throw SsiException(
        message: '`$fieldName` property should have at least one value',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return jsonValue.map((item) => parser(item)).toList();
  }

  if (!allowSingleValue) {
    throw SsiException(
      message: '`$fieldName` must be a list',
      code: SsiExceptionType.invalidJson.code,
    );
  }

  return [parser(jsonValue)];
}

dynamic encodeListToSingleOrArray<T>(List<T> items) {
  if (items.isEmpty) {
    return <T>[];
  } else if (items.length == 1) {
    return (items.first as dynamic).toJson();
  } else {
    return items.map((item) => (item as dynamic).toJson()).toList();
  }
}

Map<String, dynamic> cleanEmpty(Map<String, dynamic> input) {
  final entries = input.entries.where((entry) => switch (entry.value) {
        null => false,
        List a => a.isNotEmpty,
        _ => true
      });

  return Map.fromEntries(entries);
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
