import 'package:flutter/material.dart';

import 'widgets/home.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SdJwtDemoApp());
}

class SdJwtDemoApp extends StatelessWidget {
  const SdJwtDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SD-JWT Demo',
      debugShowCheckedModeBanner: false,
      home: const HomePage(),
    );
  }
}
