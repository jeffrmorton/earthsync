import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:http/http.dart' as http;
import 'package:sentry_flutter/sentry_flutter.dart';
import 'package:intl/intl.dart';
import 'main.dart';

class SettingsScreen extends StatefulWidget {
  @override
  _SettingsScreenState createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  double _serverInterval = 5.0;
  double _localSmoothing = 200.0;
  double _audioVolume = 1.0;
  double _bass = 50.0;
  double _mid = 50.0;
  double _treble = 50.0;

  @override
  void initState() {
    super.initState();
    final model = Provider.of<ResonanceModel>(context, listen: false);
    _serverInterval = model.updateInterval / 1000.0;
    _localSmoothing = model.localSmoothingRate.toDouble();
    _audioVolume = model.audioVolume;
  }

  Future<void> _resetToDefaults(BuildContext context) async {
    final model = Provider.of<ResonanceModel>(context, listen: false);
    final auth = Provider.of<AuthModel>(context, listen: false);

    try {
      await http.post(
        Uri.parse('https://your-server.com/set-interval'),
        headers: {'Authorization': 'Bearer ${auth.token}', 'Content-Type': 'application/json'},
        body: jsonEncode({'interval': 5000}),
      );
      model.setLocalSmoothingRate(200);
      model.toggleLocalSmoothing(true);
      model.setAudioVolume(1.0);
      model.setPreset(null);
      model.toggleEnergySavingMode(false);
      model.setThemeMode('Dark');
      model.togglePerformanceMode(false);
      model.toggleBackgroundAudio(false);
      model.toggleHighContrastMode(false);
      model.setLocale(Locale('en'));
      model.setSoundscape('None');
      model.togglePredictiveMode(false);
      model.setAudioEqualizer({'bass': 50, 'mid': 50, 'treble': 50});

      setState(() {
        _serverInterval = 5.0;
        _localSmoothing = 200.0;
        _audioVolume = 1.0;
        _bass = 50.0;
        _mid = 50.0;
        _treble = 50.0;
      });
    } catch (e) {
      model._errorMessage = 'Reset failed: $e';
      await Sentry.captureException(e);
      model.notifyListeners();
    }
  }

  void _showErrorDialog(String message) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(Intl.message('error'), style: TextStyle(color: Colors.white)),
        content: Text(message, style: TextStyle(color: Colors.white)),
        backgroundColor: Colors.grey[800],
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('OK', style: TextStyle(color: Colors.teal[300])),
          ),
        ],
      ),
    );
  }

  Future<String> _fetchApiKey() async {
    final token = Provider.of<AuthModel>(context, listen: false).token;
    final response = await http.post(
      Uri.parse('https://your-server.com/register-api-key'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body)['api_key'];
    } else {
      throw Exception('Failed to fetch API key');
    }
  }

  @override
  Widget build(BuildContext context) {
    final model = Provider.of<ResonanceModel>(context);
    final auth = Provider.of<AuthModel>(context);

    if (model.errorMessage.isNotEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _showErrorDialog(model.errorMessage));
      model._errorMessage = '';
    }

    return Scaffold(
      appBar: AppBar(title: Text(Intl.message('settings'))),
      body: Container(
        decoration: BoxDecoration(
          gradient: model.themeMode == 'Earth'
              ? LinearGradient(colors: [Colors.green[800]!, Colors.brown[900]!], begin: Alignment.topCenter, end: Alignment.bottomCenter)
              : LinearGradient(colors: [model.themeMode == 'Dark' ? Colors.teal[900]! : Colors.teal[700]!, model.themeMode == 'Dark' ? Colors.black : Colors.white], begin: Alignment.topCenter, end: Alignment.bottomCenter),
        ),
        child: ListView(
          padding: EdgeInsets.all(16.0),
          children: [
            ListTile(
              title: Text(Intl.message('strobing'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.strobingEnabled,
                onChanged: (_) {
                  model.toggleStrobing();
                  if (model.strobingEnabled) HapticFeedback.lightImpact();
                },
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('server_interval'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: Column(
                children: [
                  Slider(
                    value: _serverInterval,
                    min: 1.0,
                    max: 60.0,
                    divisions: 590,
                    label: '${_serverInterval.toStringAsFixed(1)}s',
                    onChanged: (value) => setState(() => _serverInterval = value),
                    onChangeEnd: (value) async {
                      try {
                        final token = auth.token;
                        final response = await http.post(
                          Uri.parse('https://your-server.com/set-interval'),
                          headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
                          body: jsonEncode({'interval': (value * 1000).round()}),
                        );
                        if (response.statusCode != 200) throw Exception('Failed to set interval: ${response.body}');
                      } catch (e) {
                        model._errorMessage = 'Interval update failed: $e';
                        await Sentry.captureException(e);
                        model.notifyListeners();
                      }
                    },
                    activeColor: Colors.teal[300],
                  ),
                  Text('Current: ${(model.updateInterval / 1000).toStringAsFixed(1)}s', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black54 : (model.themeMode == 'Light' ? Colors.black54 : Colors.white70))),
                ],
              ),
            ),
            ListTile(
              title: Text(Intl.message('local_smoothing'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.localSmoothingEnabled,
                onChanged: (value) => model.toggleLocalSmoothing(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('local_smoothing_rate'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: Column(
                children: [
                  Slider(
                    value: _localSmoothing,
                    min: 50.0,
                    max: 1000.0,
                    divisions: 95,
                    label: '${_localSmoothing.round()}ms',
                    onChanged: model.localSmoothingEnabled ? (value) => setState(() => _localSmoothing = value) : null,
                    onChangeEnd: (value) => model.setLocalSmoothingRate(value.round()),
                    activeColor: Colors.teal[300],
                    inactiveColor: Colors.grey[600],
                  ),
                  Text('Current: ${model.localSmoothingRate}ms', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black54 : (model.themeMode == 'Light' ? Colors.black54 : Colors.white70))),
                ],
              ),
            ),
            ListTile(
              title: Text(Intl.message('audio_volume'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: Slider(
                value: _audioVolume,
                min: 0.0,
                max: 1.0,
                divisions: 100,
                label: '${(_audioVolume * 100).round()}%',
                onChanged: (value) => setState(() => _audioVolume = value),
                onChangeEnd: (value) => model.setAudioVolume(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text('Equalizer', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: Column(
                children: [
                  Text('Bass', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
                  Slider(
                    value: _bass,
                    min: 0.0,
                    max: 100.0,
                    divisions: 100,
                    label: '${_bass.round()}',
                    onChanged: (value) => setState(() => _bass = value),
                    onChangeEnd: (value) => model.setAudioEqualizer({'bass': value.round(), 'mid': _mid.round(), 'treble': _treble.round()}),
                    activeColor: Colors.teal[300],
                  ),
                  Text('Mid', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
                  Slider(
                    value: _mid,
                    min: 0.0,
                    max: 100.0,
                    divisions: 100,
                    label: '${_mid.round()}',
                    onChanged: (value) => setState(() => _mid = value),
                    onChangeEnd: (value) => model.setAudioEqualizer({'bass': _bass.round(), 'mid': value.round(), 'treble': _treble.round()}),
                    activeColor: Colors.teal[300],
                  ),
                  Text('Treble', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
                  Slider(
                    value: _treble,
                    min: 0.0,
                    max: 100.0,
                    divisions: 100,
                    label: '${_treble.round()}',
                    onChanged: (value) => setState(() => _treble = value),
                    onChangeEnd: (value) => model.setAudioEqualizer({'bass': _bass.round(), 'mid': _mid.round(), 'treble': value.round()}),
                    activeColor: Colors.teal[300],
                  ),
                ],
              ),
            ),
            ListTile(
              title: Text(Intl.message('preset_mode'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: DropdownButton<String?>(
                value: model.presetMode,
                items: [null, ...model.presets.keys].map((mode) => DropdownMenuItem(value: mode, child: Text(mode ?? 'Live', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))))).toList(),
                onChanged: (value) => model.setPreset(value),
                dropdownColor: model.highContrastMode && model.themeMode == 'Light' ? Colors.white : (model.themeMode == 'Light' ? Colors.grey[200] : Colors.grey[800]),
              ),
            ),
            ListTile(
              title: Text(Intl.message('predictive_mode'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.predictiveMode,
                onChanged: (value) => model.togglePredictiveMode(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('energy_saving'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.energySavingMode,
                onChanged: (value) => model.toggleEnergySavingMode(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('performance_mode'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.performanceMode,
                onChanged: (value) => model.togglePerformanceMode(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('background_audio'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.backgroundAudio,
                onChanged: (value) => model.toggleBackgroundAudio(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('high_contrast'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: model.highContrastMode,
                onChanged: (value) => model.toggleHighContrastMode(value),
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text(Intl.message('theme'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: DropdownButton<String>(
                value: model.themeMode,
                items: ['Dark', 'Light', 'Earth'].map((mode) => DropdownMenuItem(value: mode, child: Text(mode, style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))))).toList(),
                onChanged: (value) => model.setThemeMode(value!),
                dropdownColor: model.highContrastMode && model.themeMode == 'Light' ? Colors.white : (model.themeMode == 'Light' ? Colors.grey[200] : Colors.grey[800]),
              ),
            ),
            ListTile(
              title: Text(Intl.message('language'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: DropdownButton<Locale>(
                value: model.locale,
                items: [Locale('en'), Locale('es')].map((locale) => DropdownMenuItem(value: locale, child: Text(locale.languageCode == 'en' ? 'English' : 'Español', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))))).toList(),
                onChanged: (value) => model.setLocale(value!),
                dropdownColor: model.highContrastMode && model.themeMode == 'Light' ? Colors.white : (model.themeMode == 'Light' ? Colors.grey[200] : Colors.grey[800]),
              ),
            ),
            ListTile(
              title: Text(Intl.message('soundscape'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: DropdownButton<String?>(
                value: model.soundscape,
                items: model.soundscapes.keys.map((sound) => DropdownMenuItem(value: sound, child: Text(sound, style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))))).toList(),
                onChanged: (value) => model.setSoundscape(value),
                dropdownColor: model.highContrastMode && model.themeMode == 'Light' ? Colors.white : (model.themeMode == 'Light' ? Colors.grey[200] : Colors.grey[800]),
              ),
            ),
            ListTile(
              title: Text(Intl.message('notifications'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: Switch(
                value: true,
                onChanged: (value) async {
                  try {
                    value ? await FirebaseMessaging.instance.subscribeToTopic('earthsync') : await FirebaseMessaging.instance.unsubscribeFromTopic('earthsync');
                  } catch (e) {
                    model._errorMessage = 'Notification toggle failed: $e';
                    await Sentry.captureException(e);
                    model.notifyListeners();
                  }
                },
                activeColor: Colors.teal[300],
              ),
            ),
            ListTile(
              title: Text('Device Integration', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => DeviceIntegrationScreen())),
            ),
            ListTile(
              title: Text('API Key', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              subtitle: FutureBuilder<String>(
                future: _fetchApiKey(),
                builder: (context, snapshot) => snapshot.hasData
                    ? Text(snapshot.data!, style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black54 : (model.themeMode == 'Light' ? Colors.black54 : Colors.white70)))
                    : CircularProgressIndicator(),
              ),
            ),
            ListTile(
              title: Text(Intl.message('reset'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              trailing: ElevatedButton(
                onPressed: () => _resetToDefaults(context),
                style: ElevatedButton.styleFrom(backgroundColor: Colors.teal[700], shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))),
                child: Text(Intl.message('reset'), style: TextStyle(color: Colors.white)),
              ),
            ),
            ListTile(
              title: Text(Intl.message('logout'), style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
              onTap: () async {
                try {
                  final prefs = await SharedPreferences.getInstance();
                  await prefs.remove('token');
                  Provider.of<AuthModel>(context, listen: false).notifyListeners();
                  Navigator.pop(context);
                } catch (e) {
                  model._errorMessage = 'Logout failed: $e';
                  await Sentry.captureException(e);
                  model.notifyListeners();
                }
              },
            ),
          ],
        ),
      ),
    );
  }
}