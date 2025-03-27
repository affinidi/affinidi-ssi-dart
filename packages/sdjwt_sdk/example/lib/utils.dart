import 'dart:convert';

import 'package:sdjwt_sdk/sdjwt_sdk.dart';

String formatSdJwt(String jwt) {
  if (jwt.isEmpty) return jwt;
  return jwt.replaceAll('~', '~\n');
}

Future<Map<String, String>> signSdJwt({
  required String keyMaterial,
  required SdJwtSignAlgorithm algorithm,
  required Map<String, dynamic> claims,
  required Map<String, bool> selectedDisclosures,
}) async {
  if (keyMaterial.isEmpty) {
    throw 'Key material is required';
  }

  // Create private key for signing
  final issuerKey = SdPrivateKey(
    keyMaterial,
    algorithm,
  );

  // Create SD-JWT handler
  final handler = SdJwtHandlerV1();

  // Sign claims with selective disclosure
  final sdJwtResult = handler.sign(
    claims: claims,
    disclosureFrame: {
      "_sd": selectedDisclosures.keys
          .where((k) => selectedDisclosures[k]!)
          .toList()
    },
    signer: SDKeySigner(issuerKey),
  );

  // Get compact SD-JWT representation
  final serialized = sdJwtResult.serialized;

  // Parse the SD-JWT to extract claims
  final parsedSdJwt = SdJwt.parse(serialized);
  final decodedSdJwt = prettyPrint({
    'claims': parsedSdJwt.claims,
    'serialized': parsedSdJwt.serialized,
  });

  return {
    'sdJwt': serialized,
    'decodedSdJwt': decodedSdJwt,
  };
}

Future<Map<String, String>> verifySdJwt({
  required String keyMaterial,
  required SdJwtSignAlgorithm algorithm,
  required String sdJwt,
}) async {
  if (keyMaterial.isEmpty) {
    throw 'Key material is required';
  }
  if (sdJwt.isEmpty) {
    throw 'No SD-JWT to verify';
  }

  // Create public key for verification
  final verifierKey = SdPublicKey(
    keyMaterial,
    algorithm,
  );

  // Create SD-JWT handler
  final handler = SdJwtHandlerV1();

  // Verify the SD-JWT and its signature
  final result = handler.decodeAndVerify(
    sdJwtToken: sdJwt,
    verifier: SDKeyVerifier(verifierKey),
  );

  return {
    'verificationResult': 'Verification: Success',
    'verificationDetails': formatVerificationDetails(result),
  };
}

String formatVerificationDetails(dynamic result) {
  if (result is String) {
    return result;
  }

  try {
    if (result is Map<String, dynamic>) {
      return prettyPrint(result);
    } else {
      final Map<String, dynamic> formattedResult = {
        'verified': true,
      };

      if (result is SdJwt) {
        final sdJwt = result;
        // Extract claims from SD-JWT
        formattedResult['claims'] = sdJwt.claims;

        if (sdJwt.disclosures.isNotEmpty) {
          // Extract disclosures from SD-JWT
          final disclosureMap = <String, dynamic>{};
          for (final disclosure in sdJwt.disclosures) {
            disclosureMap[disclosure.pointer.toString()] =
                disclosure.toString();
          }
          formattedResult['disclosures'] = disclosureMap;
        }
      }

      return prettyPrint(formattedResult);
    }
  } catch (e) {
    return 'Verification failed. Error: $e';
  }
}

Map<String, dynamic> flattenClaims(Map<String, dynamic> json,
    {String prefix = ''}) {
  final flatMap = <String, dynamic>{};
  json.forEach((key, value) {
    final fullKey = prefix.isEmpty ? key : '$prefix.$key';
    if (value is Map<String, dynamic>) {
      flatMap.addAll(flattenClaims(value, prefix: fullKey));
    } else if (value is List) {
      for (var i = 0; i < value.length; i++) {
        final itemKey = '$fullKey[$i]';
        if (value[i] is Map<String, dynamic>) {
          flatMap.addAll(flattenClaims(value[i], prefix: itemKey));
        } else {
          flatMap[itemKey] = value[i];
        }
      }
    } else {
      flatMap[fullKey] = value;
    }
  });
  return flatMap;
}

String prettyPrint(Map<String, dynamic> json) {
  try {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert(json);
  } catch (e) {
    final buffer = StringBuffer();
    _prettyPrintObject(json, buffer, 0);
    return buffer.toString();
  }
}

void _prettyPrintObject(dynamic obj, StringBuffer buffer, int indent) {
  final spaces = ' ' * (indent * 2);

  if (obj is Map) {
    buffer.write('{');
    if (obj.isNotEmpty) {
      buffer.writeln();
      int i = 0;
      obj.forEach((key, value) {
        buffer.write('$spaces  "$key": ');
        _prettyPrintObject(value, buffer, indent + 1);
        if (i < obj.length - 1) {
          buffer.writeln(',');
        } else {
          buffer.writeln();
        }
        i++;
      });
      buffer.write('$spaces}');
    } else {
      buffer.write('}');
    }
  } else if (obj is List) {
    buffer.write('[');
    if (obj.isNotEmpty) {
      buffer.writeln();
      for (int i = 0; i < obj.length; i++) {
        buffer.write('$spaces  ');
        _prettyPrintObject(obj[i], buffer, indent + 1);
        if (i < obj.length - 1) {
          buffer.writeln(',');
        } else {
          buffer.writeln();
        }
      }
      buffer.write('$spaces]');
    } else {
      buffer.write(']');
    }
  } else if (obj is String) {
    buffer.write('"${obj.replaceAll('"', '\\"')}"');
  } else {
    buffer.write(obj);
  }
}
