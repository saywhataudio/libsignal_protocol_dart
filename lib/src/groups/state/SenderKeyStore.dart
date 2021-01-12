import 'dart:async';

import '../SenderKeyName.dart';
import 'SenderKeyRecord.dart';

abstract class SenderKeyStore {
  void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record);

  FutureOr<SenderKeyRecord> loadSenderKey(SenderKeyName senderKeyName);
}
