import 'dart:async';

import '../SignalProtocolAddress.dart';
import 'SessionRecord.dart';

abstract class SessionStore {
  FutureOr<SessionRecord> loadSession(SignalProtocolAddress address);

  FutureOr<List<int>> getSubDeviceSessions(String name);

  FutureOr<void> storeSession(SignalProtocolAddress address, SessionRecord record);

  FutureOr<bool> containsSession(SignalProtocolAddress address);

  FutureOr<void> deleteSession(SignalProtocolAddress address);

  FutureOr<void> deleteAllSessions(String name);
}
