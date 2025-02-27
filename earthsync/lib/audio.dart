import 'package:flutter/services.dart';
import 'package:just_audio_background/just_audio_background.dart';

class BinauralAudio {
  static const MethodChannel _channel = MethodChannel('earthsync/binaural');
  final VoidCallback onUpdate;

  BinauralAudio({required this.onUpdate}) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'audioUpdate') onUpdate();
    });
  }

  Future<void> setFrequency(double frequency) async {
    await _channel.invokeMethod('setFrequency', {'frequency': frequency});
  }

  Future<void> setVolume(double volume) async {
    await _channel.invokeMethod('setVolume', {'volume': volume});
  }

  Future<void> setBackground(bool enabled) async {
    await _channel.invokeMethod('setBackground', {'enabled': enabled});
  }

  Future<void> setEqualizer(Map<String, int> settings) async {
    await _channel.invokeMethod('setEqualizer', settings);
  }

  Future<void> dispose() async {
    await _channel.invokeMethod('dispose');
  }
}