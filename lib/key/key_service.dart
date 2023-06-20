/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import '../rsa/rsa_private_key.dart';
import 'key_platform.dart';

class KeyService {
  static const _keyPrefix = 'com.mytiki.idp';
  final KeyPlatform _platform;

  KeyService(this._platform);

  Future<RsaPrivateKey> generate() async {
    String key = await _platform.generate();
    return RsaPrivateKey.decode(key);
  }

  Future<RsaPrivateKey?> get(String id) async {
    String? key = await _platform.read('$_keyPrefix.${id}');
    return key != null ? RsaPrivateKey.decode(key) : null;
  }

  Future<void> save(String id, RsaPrivateKey key) =>
      _platform.write('$_keyPrefix.${id}', key.encode());
}
