/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

class Registry {
  String appKeyId;
  List<String> addresses;

  Registry(this.appKeyId, this.addresses);

  @override
  String toString() {
    return 'Registry{appKeyId: $appKeyId, addresses: $addresses}';
  }
}
