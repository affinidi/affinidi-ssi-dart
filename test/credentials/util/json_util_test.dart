import 'dart:convert';

import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:ssi/src/util/json_util.dart';
import 'package:test/test.dart';

void main() {
  // group('Test getters', () {
  //   test('getObjectWithIdList, single item with id', () async {
  //     final json = {
  //       'credentialSubject': {
  //         'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
  //         'degree': {
  //           'type': 'BachelorDegree',
  //           'name': 'Bachelor of Science and Arts'
  //         }
  //       },
  //     };
  //
  //     var actual = getObjectWithIdList(
  //       json,
  //       'credentialSubject',
  //       allowSingleValue: true,
  //     );
  //
  //     expect(jsonDecode(jsonEncode(actual)), [
  //       ObjectWithId(
  //         id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
  //         otherFields: {
  //           'degree': {
  //             'type': 'BachelorDegree',
  //             'name': 'Bachelor of Science and Arts'
  //           },
  //         },
  //       ).toJson(),
  //     ]);
  //   });
  //
  //   test('getObjectWithIdList, single item no id', () async {
  //     final json = {
  //       'credentialSubject': {
  //         'degree': {
  //           'type': 'BachelorDegree',
  //           'name': 'Bachelor of Science and Arts'
  //         }
  //       },
  //     };
  //
  //     var actual = getObjectWithIdList(
  //       json,
  //       'credentialSubject',
  //       allowSingleValue: true,
  //     );
  //
  //     expect(jsonDecode(jsonEncode(actual)), [
  //       ObjectWithId(
  //         otherFields: {
  //           'degree': {
  //             'type': 'BachelorDegree',
  //             'name': 'Bachelor of Science and Arts'
  //           },
  //         },
  //       ).toJson(),
  //     ]);
  //   });
  //
  //   test('getObjectWithIdList, list', () async {
  //     final json = {
  //       'credentialSubject': [
  //         {
  //           'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
  //           'degree': {
  //             'type': 'BachelorDegree',
  //             'name': 'Bachelor of Science and Arts'
  //           }
  //         },
  //         {
  //           'degree': {
  //             'type': 'BachelorDegree2',
  //             'name': 'Bachelor of Science and Arts2'
  //           }
  //         },
  //       ]
  //     };
  //
  //     var actual = getObjectWithIdList(
  //       json,
  //       'credentialSubject',
  //       allowSingleValue: true,
  //     );
  //
  //     expect(jsonDecode(jsonEncode(actual)), [
  //       ObjectWithId(
  //         id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
  //         otherFields: {
  //           'degree': {
  //             'type': 'BachelorDegree',
  //             'name': 'Bachelor of Science and Arts'
  //           },
  //         },
  //       ).toJson(),
  //       ObjectWithId(
  //         otherFields: {
  //           'degree': {
  //             'type': 'BachelorDegree2',
  //             'name': 'Bachelor of Science and Arts2'
  //           },
  //         },
  //       ).toJson(),
  //     ]);
  //   });
  //
  //   test('getObjectWithIdList, empty list', () async {
  //     final json = {'credentialSubject': []};
  //
  //     var actual = getObjectWithIdList(
  //       json,
  //       'credentialSubject',
  //       allowSingleValue: true,
  //     );
  //
  //     expect(actual, []);
  //   });
  //
  //   test('getObjectWithIdList, missing mandatory', () async {
  //     final json = {'credentialSubject': []};
  //
  //     doGet() => getObjectWithIdList(
  //           json,
  //           'missing',
  //           allowSingleValue: true,
  //           mandatory: true,
  //         );
  //
  //     expect(
  //       doGet,
  //       throwsA(
  //         isA<SsiException>().having(
  //           (error) => error.code,
  //           'code',
  //           SsiExceptionType.invalidJson.code,
  //         ),
  //       ),
  //     );
  //   });
  // });
}
