/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'dart:convert';

import '../rsa/rsa_private_key.dart';
import 'key_model.dart';
import 'key_platform.dart';

class KeyService {
  static const _keyPrefix = 'com.mytiki.idp';
  final KeyPlatform _platform;

  KeyService(this._platform);

  Future<RsaPrivateKey> generate() async {
    String key = await _platform.generate();
    return RsaPrivateKey.decode(key);
  }

  Future<KeyModel?> get(String id) async {
    String? json = await _platform.read('$_keyPrefix.$id');
    return json != null ? KeyModel.fromMap(jsonDecode(json)) : null;
  }

  Future<void> save(String id, KeyModel key) =>
      _platform.write('$_keyPrefix.$id', jsonEncode(key.toMap()));
}
