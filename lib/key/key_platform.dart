/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

abstract class KeyPlatform {
  Future<String> generate();

  Future<void> write(String key, String value);

  Future<String?> read(String key);
}
