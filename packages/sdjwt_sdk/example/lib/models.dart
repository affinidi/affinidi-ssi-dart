import 'consts.dart';

class SampleCase {
  final String name;

  final Map<String, dynamic> claims;

  const SampleCase({
    required this.name,
    required this.claims,
  });
}

class SampleCases {
  static final List<SampleCase> predefined = [
    SampleCase(
      name: 'Basic Profile',
      claims: basicProfileClaims,
    ),
    SampleCase(
      name: 'Multiple Contact Points',
      claims: multipleContactPointsClaims,
    ),
    SampleCase(
      name: 'Complex Identity',
      claims: complexIdentityClaims,
    ),
  ];
}

enum KeyType {
  rsa,
  ecdsa,
}

extension KeyTypeExtension on KeyType {
  String toDisplayString() {
    switch (this) {
      case KeyType.rsa:
        return 'RSA';
      case KeyType.ecdsa:
        return 'ECDSA';
    }
  }
}
