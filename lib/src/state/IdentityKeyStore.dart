import 'dart:async';

import '../IdentityKey.dart';
import '../IdentityKeyPair.dart';
import '../SignalProtocolAddress.dart';

enum Direction { SENDING, RECEIVING }

abstract class IdentityKeyStore {
  FutureOr<IdentityKeyPair> getIdentityKeyPair();
  FutureOr<int> getLocalRegistrationId();
  FutureOr<bool> saveIdentity(SignalProtocolAddress address, IdentityKey identityKey);
  FutureOr<bool> isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction);
  FutureOr<IdentityKey> getIdentity(SignalProtocolAddress address);
}
