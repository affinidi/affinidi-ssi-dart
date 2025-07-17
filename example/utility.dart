import 'dart:convert';

void printJsonFrom(Object object) {
  const jsonEncoder = JsonEncoder.withIndent('  ');
  print(jsonEncoder.convert(object));
}
