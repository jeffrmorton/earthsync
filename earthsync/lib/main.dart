import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:provider/provider.dart';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:share_plus/share.dart';
import 'package:sqflite/sqflite.dart';
import 'package:just_audio/just_audio.dart';
import 'package:just_audio_background/just_audio_background.dart';
import 'package:sentry_flutter/sentry_flutter.dart';
import 'package:firebase_performance/firebase_performance.dart';
import 'package:firebase_crashlytics/firebase_crashlytics.dart';
import 'package:flutter_blue/flutter_blue.dart';
import 'package:intl/intl.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'resonance_graph.dart';
import 'resonance_globe.dart';
import 'settings.dart';
import 'audio.dart';

Future<void> main() async {
  await JustAudioBackground.init(
    androidNotificationChannelId: 'com.yourdomain.earthsync.audio',
    androidNotificationChannelName: 'EarthSync Audio',
    androidNotificationOngoing: true,
  );
  await SentryFlutter.init(
    (options) => options.dsn = 'https://your-sentry-dsn@sentry.io/your-project-id',
    appRunner: () async {
      WidgetsFlutterBinding.ensureInitialized();
      await Firebase.initializeApp();
      FlutterError.onError = FirebaseCrashlytics.instance.recordFlutterError;
      runApp(
        MultiProvider(
          providers: [
            ChangeNotifierProvider(create: (_) => ResonanceModel()),
            ChangeNotifierProvider(create: (_) => AuthModel()),
          ],
          child: MyApp(),
        ),
      );
    },
  );
}

class AuthModel with ChangeNotifier {
  String? _token;
  String get token => _token ?? '';

  Future<void> login(String username, String password) async {
    try {
      final response = await http.post(
        Uri.parse('https://your-server.com/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'username': username, 'password': password}),
      );
      if (response.statusCode == 200) {
        _token = jsonDecode(response.body)['token'];
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('token', _token!);
        notifyListeners();
      } else {
        throw Exception('Login failed: ${response.body}');
      }
    } catch (e) {
      await Sentry.captureException(e);
      throw Exception('Login error: $e');
    }
  }

  Future<void> loadToken() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _token = prefs.getString('token');
      notifyListeners();
    } catch (e) {
      await Sentry.captureException(e);
    }
  }
}

class DeviceConfig {
  final String name;
  final String serviceId;
  final String? controlCharacteristicId;
  final String? feedbackCharacteristicId;

  DeviceConfig({required this.name, required this.serviceId, this.controlCharacteristicId, this.feedbackCharacteristicId});
}

class DeviceIntegrationManager {
  DeviceConfig? currentDeviceConfig;
  BluetoothDevice? currentDevice;
  BluetoothCharacteristic? controlCharacteristic;
  BluetoothCharacteristic? feedbackCharacteristic;

  void selectDeviceConfig(DeviceConfig config) {
    currentDeviceConfig = config;
  }

  Future<void> connectToDevice(BluetoothDevice device) async {
    currentDevice = device;
    await device.connect();
    final services = await device.discoverServices();
    if (currentDeviceConfig != null) {
      for (var s in services) {
        if (s.uuid.toString().toLowerCase() == currentDeviceConfig!.serviceId.toLowerCase()) {
          for (var c in s.characteristics) {
            if (currentDeviceConfig!.controlCharacteristicId != null &&
                c.uuid.toString().toLowerCase() == currentDeviceConfig!.controlCharacteristicId!.toLowerCase()) {
              controlCharacteristic = c;
            }
            if (currentDeviceConfig!.feedbackCharacteristicId != null &&
                c.uuid.toString().toLowerCase() == currentDeviceConfig!.feedbackCharacteristicId!.toLowerCase()) {
              feedbackCharacteristic = c;
              if (c.properties.notify || c.properties.read) {
                await c.setNotifyValue(true);
                c.value.listen((value) {
                  if (value.isNotEmpty) {
                    // Handle feedback data (e.g., heart rate)
                  }
                });
              }
            }
          }
        }
      }
    }
  }

  void disconnect() {
    if (currentDevice != null) {
      currentDevice!.disconnect();
      currentDevice = null;
      controlCharacteristic = null;
      feedbackCharacteristic = null;
    }
  }

  Future<void> sendFrequency(double frequency) async {
    if (controlCharacteristic != null) {
      int freqInt = frequency.toInt();
      List<int> data = [freqInt];
      await controlCharacteristic!.write(data, withoutResponse: true);
    }
  }
}

class ResonanceModel with ChangeNotifier, WidgetsBindingObserver {
  double _frequency = 7.83;
  List<Map<String, double>> _history = [];
  bool _strobingEnabled = true;
  late BinauralAudio _audio;
  int _updateInterval = 5000;
  int _localSmoothingRate = 200;
  bool _localSmoothingEnabled = true;
  double _audioVolume = 1.0;
  String? _presetMode;
  Map<String, double> presets = {'Relax': 8.0, 'Focus': 14.0, 'Sleep': 4.0};
  bool _energySavingMode = false;
  String _themeMode = 'Dark';
  Timer? _localTimer;
  late Database _db;
  DateTime? _sessionStart;
  final _meditationPlayer = AudioPlayer();
  final _soundscapePlayer = AudioPlayer();
  bool _isOffline = false;
  String _errorMessage = '';
  String _activityState = 'Active';
  bool _performanceMode = false;
  bool _backgroundAudio = false;
  bool _highContrastMode = false;
  Locale _locale = Locale('en');
  String? _soundscape;
  Map<String, String> soundscapes = {'None': '', 'Rain': 'assets/rain.mp3', 'Forest': 'assets/forest.mp3'};
  int? _heartRate;
  bool _predictiveMode = false;
  double? _predictedFrequency;
  encrypt.Encrypter? _encrypter;
  final DeviceIntegrationManager deviceManager = DeviceIntegrationManager();

  double get frequency => _frequency;
  List<Map<String, double>> get history => _history;
  bool get strobingEnabled => _strobingEnabled;
  int get updateInterval => _updateInterval;
  int get localSmoothingRate => _localSmoothingRate;
  bool get localSmoothingEnabled => _localSmoothingEnabled;
  double get audioVolume => _audioVolume;
  String? get presetMode => _presetMode;
  bool get energySavingMode => _energySavingMode;
  String get themeMode => _themeMode;
  bool get isOffline => _isOffline;
  String get errorMessage => _errorMessage;
  bool get performanceMode => _performanceMode;
  bool get backgroundAudio => _backgroundAudio;
  bool get highContrastMode => _highContrastMode;
  Locale get locale => _locale;
  String? get soundscape => _soundscape;
  int? get heartRate => _heartRate;
  bool get predictiveMode => _predictiveMode;
  double? get predictedFrequency => _predictedFrequency;

  ResonanceModel() {
    _audio = BinauralAudio(onUpdate: notifyListeners);
    _initDb();
    _startLocalUpdates();
    _sessionStart = DateTime.now();
    _initBluetooth();
    _initEncryption();
    WidgetsBinding.instance.addObserver(this);
    FirebaseMessaging.onMessage.listen((message) {
      _errorMessage = message.notification?.body ?? '';
      notifyListeners();
    });
    _loadPreferences();
    _fetchPrediction();
  }

  Future<void> _initDb() async {
    try {
      _db = await openDatabase('earthsync.db', version: 1, onCreate: (db, version) {
        db.execute('CREATE TABLE history (id INTEGER PRIMARY KEY, frequency REAL, timestamp INTEGER)');
      });
      await _loadCachedHistory();
    } catch (e) {
      _errorMessage = 'Database initialization failed: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  Future<void> _initEncryption() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final token = prefs.getString('token');
      final response = await http.post(
        Uri.parse('https://your-server.com/key-exchange'),
        headers: {'Authorization': 'Bearer $token'},
      );
      if (response.statusCode == 200) {
        final keyHex = jsonDecode(response.body)['key'];
        final key = encrypt.Key.fromHex(keyHex);
        _encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.gcm));
      } else {
        throw Exception('Key exchange failed');
      }
    } catch (e) {
      _errorMessage = 'Encryption setup failed: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void updateFrequency(double newFreq, String timestamp, int interval, String encryptedData, String ivHex, String authTagHex) async {
    try {
      if (_encrypter != null) {
        final iv = encrypt.IV.fromHex(ivHex);
        final authTag = encrypt.IV.fromHex(authTagHex);
        final decrypted = _encrypter!.decrypt(encrypt.Encrypted.fromHex(encryptedData), iv: iv, associatedData: authTag);
        final data = jsonDecode(decrypted);
        newFreq = data['frequency'];
        timestamp = data['timestamp'];
        interval = data['interval'];
      }
      _frequency = _predictiveMode && _predictedFrequency != null ? _predictedFrequency! : (_presetMode != null ? presets[_presetMode]! : newFreq);
      _updateInterval = interval.clamp(1000, 60000);
      final time = DateTime.parse(timestamp).millisecondsSinceEpoch / 1000;
      _history.add({'time': time, 'frequency': newFreq});
      if (_history.length > 60) _history.removeAt(0);
      await _db.insert('history', {'frequency': newFreq, 'timestamp': time.toInt()});
      _audio.setFrequency(_frequency);
      if (deviceManager.controlCharacteristic != null) {
        await deviceManager.sendFrequency(_frequency);
      }
      _isOffline = false;
    } catch (e) {
      _errorMessage = 'Frequency update failed: $e';
      _isOffline = true;
      await Sentry.captureException(e);
    }
    notifyListeners();
  }

  void setLocalSmoothingRate(int rate) {
    _localSmoothingRate = rate.clamp(50, 1000);
    _startLocalUpdates();
    notifyListeners();
  }

  void toggleLocalSmoothing(bool enabled) {
    _localSmoothingEnabled = enabled;
    _startLocalUpdates();
    notifyListeners();
  }

  void setAudioVolume(double volume) {
    _audioVolume = volume.clamp(0.0, 1.0);
    _audio.setVolume(_audioVolume);
    _meditationPlayer.setVolume(_audioVolume);
    _soundscapePlayer.setVolume(_audioVolume);
    notifyListeners();
  }

  void setAudioEqualizer(Map<String, int> settings) {
    _audio.setEqualizer(settings);
    notifyListeners();
  }

  void setPreset(String? mode) {
    _presetMode = mode;
    if (mode != null) _audio.setFrequency(presets[mode]!);
    notifyListeners();
  }

  void toggleEnergySavingMode(bool enabled) {
    _energySavingMode = enabled;
    _startLocalUpdates();
    notifyListeners();
  }

  void setThemeMode(String mode) async {
    try {
      _themeMode = mode;
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('theme', mode);
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to save theme: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void setActivityState(String state) async {
    _activityState = state;
    if (_performanceMode) {
      try {
        final token = (await SharedPreferences.getInstance()).getString('token');
        await http.post(
          Uri.parse('https://your-server.com/set-interval'),
          headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
          body: jsonEncode({'interval': state == 'Active' ? 5000 : 30000, 'activity': state}),
        );
      } catch (e) {
        _errorMessage = 'Failed to update activity state: $e';
        await Sentry.captureException(e);
        notifyListeners();
      }
    }
  }

  void togglePerformanceMode(bool enabled) {
    _performanceMode = enabled;
    setActivityState(_activityState);
    notifyListeners();
  }

  void toggleBackgroundAudio(bool enabled) async {
    _backgroundAudio = enabled;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('background_audio', enabled);
      if (enabled) {
        _audio.setBackground(true);
        _meditationPlayer.setBackground(true);
        _soundscapePlayer.setBackground(true);
      } else {
        _audio.setBackground(false);
        _meditationPlayer.setBackground(false);
        _soundscapePlayer.setBackground(false);
      }
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to toggle background audio: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void toggleHighContrastMode(bool enabled) async {
    _highContrastMode = enabled;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('high_contrast', enabled);
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to toggle high contrast mode: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void setLocale(Locale locale) async {
    _locale = locale;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('locale', locale.languageCode);
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to set locale: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void setSoundscape(String? sound) async {
    _soundscape = sound;
    try {
      if (sound != null && soundscapes[sound]!.isNotEmpty) {
        await _soundscapePlayer.setAsset(soundscapes[sound]!);
        _soundscapePlayer.setVolume(_audioVolume);
        _soundscapePlayer.setLoopMode(LoopMode.all);
        _soundscapePlayer.play();
      } else {
        _soundscapePlayer.stop();
      }
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('soundscape', sound ?? 'None');
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to set soundscape: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void togglePredictiveMode(bool enabled) async {
    _predictiveMode = enabled;
    if (enabled) await _fetchPrediction();
    notifyListeners();
  }

  Future<void> _fetchPrediction() async {
    try {
      final token = (await SharedPreferences.getInstance()).getString('token');
      final response = await http.get(
        Uri.parse('https://your-server.com/predict-frequency'),
        headers: {'Authorization': 'Bearer $token'},
      );
      if (response.statusCode == 200) {
        _predictedFrequency = jsonDecode(response.body)['predicted_frequency'];
        if (_predictiveMode) _audio.setFrequency(_predictedFrequency!);
      } else {
        throw Exception('Failed to fetch prediction');
      }
    } catch (e) {
      _errorMessage = 'Prediction fetch failed: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void _startLocalUpdates() {
    _localTimer?.cancel();
    if (_localSmoothingEnabled && !_energySavingMode) {
      _localTimer = Timer.periodic(Duration(milliseconds: _localSmoothingRate), (_) {
        if (_history.isNotEmpty && _presetMode == null && !_predictiveMode) {
          _frequency += (Math.random() - 0.5) * 0.01;
          _frequency = _frequency.clamp(7.5, 8.5);
          notifyListeners();
        }
      });
    }
  }

  Future<void> _loadCachedHistory() async {
    try {
      final data = await _db.query('history', orderBy: 'timestamp DESC', limit: 60);
      _history = data.map((row) => {'time': row['timestamp']!.toDouble(), 'frequency': row['frequency'] as double}).toList();
      if (_history.isNotEmpty) _frequency = _history.first['frequency']!;
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to load cached history: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  Future<void> _loadPreferences() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _themeMode = prefs.getString('theme') ?? 'Dark';
      _backgroundAudio = prefs.getBool('background_audio') ?? false;
      _highContrastMode = prefs.getBool('high_contrast') ?? false;
      _locale = Locale(prefs.getString('locale') ?? 'en');
      _soundscape = prefs.getString('soundscape');
      if (_soundscape != null) setSoundscape(_soundscape);
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to load preferences: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  Future<void> playMeditation(int durationMinutes) async {
    try {
      await _meditationPlayer.setAsset('assets/meditation_5min.mp3');
      _meditationPlayer.setVolume(_audioVolume);
      _meditationPlayer.play();
      Timer(Duration(minutes: durationMinutes), () => _meditationPlayer.stop());
    } catch (e) {
      _errorMessage = 'Meditation playback failed: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  Future<void> logSession() async {
    try {
      final duration = DateTime.now().difference(_sessionStart!).inSeconds;
      final token = (await SharedPreferences.getInstance()).getString('token');
      final response = await http.post(
        Uri.parse('https://your-server.com/log-usage'),
        headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
        body: jsonEncode({'duration': duration, 'preset_mode': _presetMode}),
      );
      if (response.statusCode != 200) throw Exception('Failed to log session: ${response.body}');
      _sessionStart = DateTime.now();
    } catch (e) {
      _errorMessage = 'Session logging failed: $e';
      await Sentry.captureException(e);
      notifyListeners();
    }
  }

  void _initBluetooth() {
    FlutterBlue.instance.state.listen((state) {
      if (state == BluetoothState.on) {
        FlutterBlue.instance.scanResults.listen((results) {
          for (ScanResult r in results) {
            if (r.device.name.contains('Heart')) {
              r.device.connect().then((_) {
                r.device.discoverServices().then((services) {
                  for (BluetoothService s in services) {
                    if (s.uuid.toString().startsWith('180d')) {
                      for (BluetoothCharacteristic c in s.characteristics) {
                        if (c.uuid.toString().startsWith('2a37')) {
                          c.setNotifyValue(true);
                          c.value.listen((value) {
                            if (value.isNotEmpty) {
                              _heartRate = value[1];
                              if (_heartRate != null && _heartRate! > 80 && _presetMode == null) setPreset('Sleep');
                              notifyListeners();
                            }
                          });
                        }
                      }
                    }
                  }
                });
              });
            }
          }
        });
        FlutterBlue.instance.startScan();
      }
    });
  }

  void toggleStrobing() {
    _strobingEnabled = !_strobingEnabled;
    notifyListeners();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    setActivityState(state == AppLifecycleState.resumed ? 'Active' : 'Background');
  }

  @override
  void dispose() {
    _audio.dispose();
    _localTimer?.cancel();
    _meditationPlayer.dispose();
    _soundscapePlayer.dispose();
    _db.close();
    logSession();
    deviceManager.disconnect();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Consumer<ResonanceModel>(
      builder: (context, model, child) => MaterialApp(
        localizationsDelegates: [
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        supportedLocales: [Locale('en'), Locale('es')],
        locale: model.locale,
        theme: _buildTheme(model.themeMode, model.highContrastMode),
        home: SplashScreen(),
        navigatorObservers: [SentryNavigatorObserver()],
      ),
    );
  }

  ThemeData _buildTheme(String mode, bool highContrast) {
    switch (mode) {
      case 'Light':
        return ThemeData(
          primaryColor: Colors.teal[700],
          scaffoldBackgroundColor: highContrast ? Colors.white : Colors.grey[200],
          textTheme: TextTheme(bodyMedium: TextStyle(color: highContrast ? Colors.black : Colors.black87)),
        );
      case 'Earth':
        return ThemeData(
          primaryColor: Colors.green[800],
          scaffoldBackgroundColor: highContrast ? Colors.black : Colors.brown[900],
          textTheme: TextTheme(bodyMedium: TextStyle(color: highContrast ? Colors.white : Colors.white70)),
        );
      default:
        return ThemeData(
          primaryColor: Colors.teal[900],
          scaffoldBackgroundColor: highContrast ? Colors.black : Colors.grey[900],
          textTheme: TextTheme(bodyMedium: TextStyle(color: highContrast ? Colors.white : Colors.white70)),
        );
    }
  }
}

class SplashScreen extends StatefulWidget {
  @override
  _SplashScreenState createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    Future.delayed(Duration(seconds: 4), () {
      if (mounted) {
        Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => AuthWrapper()));
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(colors: [Colors.teal[900]!, Colors.black], begin: Alignment.topCenter, end: Alignment.bottomCenter),
        ),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Image.asset(
                'assets/splash_earth.png',
                width: 250,
                height: 250,
                fit: BoxFit.contain,
              )
                  .animate()
                  .fadeIn(duration: 1200.ms, curve: Curves.easeInOut)
                  .scale(begin: Offset(0.8, 0.8), end: Offset(1.0, 1.0), duration: 1200.ms)
                  .then()
                  .rotate(
                    duration: 2800.ms,
                    begin: 0,
                    end: 1,
                    curve: Curves.easeInOutSine,
                  )
                  .effect(
                    duration: 2800.ms,
                    effect: PulseEffect(
                      scale: 1.05,
                      frequency: 2,
                    ),
                  ),
              SizedBox(height: 20),
              Text(
                'EarthSync',
                style: TextStyle(
                  fontSize: 28,
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  shadows: [Shadow(color: Colors.teal[300]!, blurRadius: 4)],
                ),
              )
                  .animate()
                  .fadeIn(duration: 1800.ms, delay: 600.ms, curve: Curves.easeInOut)
                  .slideY(begin: 0.2, end: 0.0, duration: 1800.ms),
            ],
          ),
        ),
      ),
    );
  }
}

class AuthWrapper extends StatefulWidget {
  @override
  _AuthWrapperState createState() => _AuthWrapperState();
}

class _AuthWrapperState extends State<AuthWrapper> {
  @override
  void initState() {
    super.initState();
    Provider.of<AuthModel>(context, listen: false).loadToken();
    FirebaseMessaging.instance.requestPermission().catchError((e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'Notification permission error: $e';
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
    });
    FirebaseMessaging.instance.subscribeToTopic('earthsync').catchError((e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'Subscription error: $e';
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
    });
  }

  @override
  Widget build(BuildContext context) {
    final auth = Provider.of<AuthModel>(context);
    return auth.token.isEmpty ? LoginScreen() : ResonanceScreen();
  }
}

class LoginScreen extends StatelessWidget {
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(gradient: LinearGradient(colors: [Colors.teal[900]!, Colors.black], begin: Alignment.topCenter, end: Alignment.bottomCenter)),
        child: Padding(
          padding: EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(Intl.message('app_title'), style: TextStyle(fontSize: 28, color: Colors.white, fontWeight: FontWeight.bold)),
              SizedBox(height: 20),
              TextField(
                controller: _usernameController,
                decoration: InputDecoration(labelText: Intl.message('username'), labelStyle: TextStyle(color: Colors.white70), filled: true, fillColor: Colors.white12),
                style: TextStyle(color: Colors.white),
              ),
              SizedBox(height: 10),
              TextField(
                controller: _passwordController,
                decoration: InputDecoration(labelText: Intl.message('password'), labelStyle: TextStyle(color: Colors.white70), filled: true, fillColor: Colors.white12),
                style: TextStyle(color: Colors.white),
                obscureText: true,
              ),
              SizedBox(height: 20),
              ElevatedButton(
                onPressed: () async {
                  try {
                    await Provider.of<AuthModel>(context, listen: false).login(_usernameController.text, _passwordController.text);
                  } catch (e) {
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.toString())));
                  }
                },
                style: ElevatedButton.styleFrom(backgroundColor: Colors.teal[700]),
                child: Text(Intl.message('login')),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class ResonanceScreen extends StatefulWidget {
  @override
  _ResonanceScreenState createState() => _ResonanceScreenState();
}

class _ResonanceScreenState extends State<ResonanceScreen> with SingleTickerProviderStateMixin {
  late WebSocketChannel channel;
  late AnimationController _strobeController;
  bool _isMounted = true;
  int _selectedTab = 0;
  final _performanceTrace = FirebasePerformance.instance.newTrace('app_performance');

  @override
  void initState() {
    super.initState();
    final token = Provider.of<AuthModel>(context, listen: false).token;
    _connectWebSocket(token);
    _strobeController = AnimationController(vsync: this, duration: Duration(milliseconds: 127))
      ..addListener(() => setState(() {}));
    _performanceTrace.start();
  }

  void _connectWebSocket(String token) {
    try {
      channel = WebSocketChannel.connect(Uri.parse('wss://your-server.com/schumann-stream?token=$token'));
      channel.stream.listen(
        (message) {
          if (!_isMounted) return;
          final parts = message.split(':');
          if (parts.length == 3) {
            Provider.of<ResonanceModel>(context, listen: false).updateFrequency(
              0, // Placeholder, will be decrypted
              '', // Placeholder
              0,  // Placeholder
              parts[0], // encryptedData
              parts[1], // ivHex
              parts[2]  // authTagHex
            );
          }
          if (Provider.of<ResonanceModel>(context, listen: false).strobingEnabled && !Provider.of<ResonanceModel>(context, listen: false).energySavingMode) {
            _strobeController.duration = Duration(milliseconds: (1000 / Provider.of<ResonanceModel>(context, listen: false).frequency).clamp(33, 1000).round());
            if (!_strobeController.isAnimating) _strobeController.repeat();
          }
        },
        onError: (e) {
          Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'WebSocket error: $e';
          Provider.of<ResonanceModel>(context, listen: false)._isOffline = true;
          Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
          Sentry.captureException(e);
          Future.delayed(Duration(seconds: 5), () => _connectWebSocket(token));
        },
        onDone: () {
          Provider.of<ResonanceModel>(context, listen: false)._isOffline = true;
          Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
          Future.delayed(Duration(seconds: 5), () => _connectWebSocket(token));
        },
        cancelOnError: false,
      );
    } catch (e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'WebSocket connection failed: $e';
      Provider.of<ResonanceModel>(context, listen: false)._isOffline = true;
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
    }
  }

  Future<List<Map<String, double>>> _fetchHistory() async {
    try {
      final token = Provider.of<AuthModel>(context, listen: false).token;
      final response = await http.get(
        Uri.parse('https://your-server.com/history/24'),
        headers: {'Authorization': 'Bearer $token'},
      );
      if (response.statusCode != 200) throw Exception('Failed to fetch history: ${response.body}');
      final data = jsonDecode(response.body) as List;
      return data.map((e) => {'time': DateTime.parse(e['timestamp']).millisecondsSinceEpoch / 1000, 'frequency': e['frequency'].toDouble()}).toList();
    } catch (e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'History fetch failed: $e';
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
      return Provider.of<ResonanceModel>(context, listen: false).history;
    }
  }

  Future<List<Map<String, dynamic>>> _fetchUsageTrends() async {
    try {
      final token = Provider.of<AuthModel>(context, listen: false).token;
      final response = await http.get(
        Uri.parse('https://your-server.com/usage-trends'),
        headers: {'Authorization': 'Bearer $token'},
      );
      if (response.statusCode != 200) throw Exception('Failed to fetch trends: ${response.body}');
      final data = jsonDecode(response.body) as List;
      return data.map((e) => {'date': DateTime.parse(e['date']).millisecondsSinceEpoch / 1000, 'total': e['total'].toDouble()}).toList();
    } catch (e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'Trends fetch failed: $e';
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
      return [];
    }
  }

  Future<List<Map<String, dynamic>>> _fetchPresetUsage() async {
    try {
      final token = Provider.of<AuthModel>(context, listen: false).token;
      final response = await http.get(
        Uri.parse('https://your-server.com/preset-usage'),
        headers: {'Authorization': 'Bearer $token'},
      );
      if (response.statusCode != 200) throw Exception('Failed to fetch preset usage: ${response.body}');
      final data = jsonDecode(response.body) as List;
      return data.map((e) => {'preset': e['preset_mode'], 'count': e['count'].toDouble()}).toList();
    } catch (e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'Preset usage fetch failed: $e';
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
      return [];
    }
  }

  Future<Map<String, dynamic>> _fetchGlobalStats() async {
    try {
      final response = await http.get(Uri.parse('https://your-server.com/global-stats'));
      if (response.statusCode != 200) throw Exception('Failed to fetch global stats: ${response.body}');
      return jsonDecode(response.body);
    } catch (e) {
      Provider.of<ResonanceModel>(context, listen: false)._errorMessage = 'Global stats fetch failed: $e';
      Provider.of<ResonanceModel>(context, listen: false).notifyListeners();
      Sentry.captureException(e);
      return {'active_users': 0, 'average_frequency': 7.83};
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

  @override
  Widget build(BuildContext context) {
    return Consumer<ResonanceModel>(
      builder: (context, model, child) {
        if (model.errorMessage.isNotEmpty) {
          WidgetsBinding.instance.addPostFrameCallback((_) => _showErrorDialog(model.errorMessage));
          model._errorMessage = '';
        }
        return Scaffold(
          appBar: AppBar(
            title: Text(Intl.message('app_title')),
            actions: [
              IconButton(
                icon: Icon(_selectedTab == 1 ? Icons.realtime : Icons.history),
                onPressed: () => setState(() => _selectedTab = _selectedTab == 1 ? 0 : 1),
              ),
              IconButton(icon: Icon(Icons.settings), onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => SettingsScreen()))),
            ],
          ),
          body: Stack(
            children: [
              if (model.strobingEnabled && !model.energySavingMode)
                AnimatedBuilder(
                  animation: _strobeController,
                  builder: (context, child) => Container(color: Colors.teal[900]!.withOpacity(_strobeController.value * 0.2)),
                ),
              Container(
                decoration: BoxDecoration(
                  gradient: model.themeMode == 'Earth'
                      ? LinearGradient(colors: [Colors.green[800]!, Colors.brown[900]!], begin: Alignment.topCenter, end: Alignment.bottomCenter)
                      : LinearGradient(colors: [model.themeMode == 'Dark' ? Colors.teal[900]! : Colors.teal[700]!, model.themeMode == 'Dark' ? Colors.black : Colors.white], begin: Alignment.topCenter, end: Alignment.bottomCenter),
                ),
                child: SafeArea(
                  child: Column(
                    children: [
                      SizedBox(height: 20),
                      if (!model.energySavingMode) SizedBox(height: 220, child: ResonanceGlobe()),
                      Padding(
                        padding: EdgeInsets.all(16.0),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Semantics(
                              label: 'Current Frequency',
                              child: Text(
                                Intl.message('current_frequency', args: {
                                  'frequency': model.frequency.toStringAsFixed(2),
                                  'serverInterval': (model.updateInterval / 1000).toStringAsFixed(1),
                                  'localInterval': model.localSmoothingRate
                                }) + (model.isOffline ? ' (Offline)' : '') + (model.predictiveMode ? ' (Predicted)' : ''),
                                style: TextStyle(fontSize: 18, color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white)),
                              ),
                            ),
                            Text(Intl.message('source'), style: TextStyle(fontSize: 12, color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black54 : (model.themeMode == 'Light' ? Colors.black54 : Colors.white70))),
                            if (model.heartRate != null)
                              Text('Heart Rate: ${model.heartRate} bpm', style: TextStyle(fontSize: 12, color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
                          ],
                        ),
                      ),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                        children: [
                          ElevatedButton(
                            onPressed: () => model.playMeditation(5),
                            child: Text(Intl.message('meditate')),
                            style: ElevatedButton.styleFrom(backgroundColor: Colors.teal[700]),
                          ),
                          ElevatedButton(
                            onPressed: () => Share.share('EarthSync: ${model.frequency.toStringAsFixed(2)} Hz at ${DateTime.now().toIso8601String()}'),
                            child: Text(Intl.message('share')),
                            style: ElevatedButton.styleFrom(backgroundColor: Colors.teal[700]),
                          ),
                        ],
                      ),
                      Expanded(
                        child: IndexedStack(
                          index: _selectedTab,
                          children: [
                            ResonanceGraph(),
                            FutureBuilder<List<Map<String, double>>>(
                              future: _fetchHistory(),
                              builder: (context, snapshot) => snapshot.hasData
                                  ? LineChart(LineChartData(
                                      lineBarsData: [
                                        LineChartBarData(
                                          spots: snapshot.data!.map((e) => FlSpot(e['time']! - snapshot.data!.first['time']!, e['frequency']!)).toList(),
                                          isCurved: true,
                                          color: Colors.teal[300],
                                          gradient: LinearGradient(colors: [Colors.teal[300]!, Colors.teal[700]!]),
                                        ),
                                      ],
                                      minY: 7,
                                      maxY: 9,
                                    ))
                                  : Center(child: CircularProgressIndicator()),
                            ),
                            FutureBuilder<List<Map<String, dynamic>>>(
                              future: _fetchUsageTrends(),
                              builder: (context, snapshot) => snapshot.hasData
                                  ? LineChart(LineChartData(
                                      lineBarsData: [
                                        LineChartBarData(
                                          spots: snapshot.data!.map((e) => FlSpot(e['date'], e['total'] / 3600)).toList(),
                                          isCurved: true,
                                          color: Colors.teal[300],
                                        ),
                                      ],
                                      titlesData: FlTitlesData(
                                        leftTitles: AxisTitles(sideTitles: SideTitles(showTitles: true, getTitlesWidget: (value, meta) => Text('${value.toInt()}h'))),
                                        bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: true, getTitlesWidget: (value, meta) => Text(DateTime.fromMillisecondsSinceEpoch(value.toInt() * 1000).day.toString()))),
                                      ),
                                    ))
                                  : Center(child: CircularProgressIndicator()),
                            ),
                            FutureBuilder<Map<String, dynamic>>(
                              future: _fetchGlobalStats(),
                              builder: (context, snapshot) => snapshot.hasData
                                  ? Column(
                                      children: [
                                        Text('Active Users: ${snapshot.data!['active_users']}', style: TextStyle(color: model.themeMode == 'Light' ? Colors.black87 : Colors.white)),
                                        Text('Avg Frequency (24h): ${snapshot.data!['average_frequency'].toStringAsFixed(2)} Hz', style: TextStyle(color: model.themeMode == 'Light' ? Colors.black87 : Colors.white)),
                                      ],
                                    )
                                  : Center(child: CircularProgressIndicator()),
                            ),
                          ],
                        ),
                      ),
                      BottomNavigationBar(
                        currentIndex: _selectedTab,
                        onTap: (index) => setState(() => _selectedTab = index),
                        items: [
                          BottomNavigationBarItem(icon: Icon(Icons.realtime), label: 'Real-Time'),
                          BottomNavigationBarItem(icon: Icon(Icons.history), label: 'History'),
                          BottomNavigationBarItem(icon: Icon(Icons.analytics), label: 'Analytics'),
                          BottomNavigationBarItem(icon: Icon(Icons.group), label: 'Community'),
                        ],
                        backgroundColor: model.themeMode == 'Light' ? Colors.white : Colors.grey[900],
                        selectedItemColor: Colors.teal[300],
                        unselectedItemColor: model.highContrastMode && model.themeMode == 'Light' ? Colors.black54 : (model.themeMode == 'Light' ? Colors.black54 : Colors.white70),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  @override
  void dispose() {
    _isMounted = false;
    channel.sink.close();
    _strobeController.dispose();
    _performanceTrace.stop();
    super.dispose();
  }
}

class DeviceIntegrationScreen extends StatefulWidget {
  @override
  _DeviceIntegrationScreenState createState() => _DeviceIntegrationScreenState();
}

class _DeviceIntegrationScreenState extends State<DeviceIntegrationScreen> {
  List<DeviceConfig> supportedDevices = [
    DeviceConfig(
      name: 'Heart Rate Monitor',
      serviceId: '180d',
      feedbackCharacteristicId: '2a37',
    ),
    DeviceConfig(
      name: 'Visual Entrainment Device',
      serviceId: 'custom_service_id', // Placeholder, replace with actual UUID for specific device
      controlCharacteristicId: 'frequency_control_char',
    ),
  ];

  DeviceConfig? selectedDeviceConfig;
  List<ScanResult> discoveredDevices = [];

  @override
  void initState() {
    super.initState();
    _startScan();
  }

  void _startScan() {
    FlutterBlue.instance.startScan();
    FlutterBlue.instance.scanResults.listen((results) {
      setState(() {
        discoveredDevices = results.where((r) {
          return selectedDeviceConfig != null &&
              r.advertisementData.serviceUuids.any((s) => s.toLowerCase() == selectedDeviceConfig!.serviceId.toLowerCase());
        }).toList();
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    final model = Provider.of<ResonanceModel>(context);
    return Scaffold(
      appBar: AppBar(title: Text(Intl.message('device_integration'))),
      body: Column(
        children: [
          Expanded(
            child: ListView(
              children: supportedDevices.map((device) {
                return ListTile(
                  title: Text(device.name, style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
                  onTap: () {
                    setState(() {
                      selectedDeviceConfig = device;
                      discoveredDevices.clear();
                      _startScan();
                    });
                    model.deviceManager.selectDeviceConfig(device);
                  },
                );
              }).toList(),
            ),
          ),
          if (selectedDeviceConfig != null)
            Expanded(
              child: ListView(
                children: discoveredDevices.map((result) {
                  return ListTile(
                    title: Text(result.device.name.isNotEmpty ? result.device.name : 'Unknown Device', style: TextStyle(color: model.highContrastMode && model.themeMode == 'Light' ? Colors.black : (model.themeMode == 'Light' ? Colors.black87 : Colors.white))),
                    onTap: () async {
                      try {
                        await model.deviceManager.connectToDevice(result.device);
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Connected to ${result.device.name}')));
                      } catch (e) {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to connect: $e')));
                      }
                    },
                  );
                }).toList(),
              ),
            ),
          ElevatedButton(
            onPressed: model.deviceManager.currentDevice != null ? () {
              model.deviceManager.disconnect();
              setState(() {
                discoveredDevices.clear();
                selectedDeviceConfig = null;
              });
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Disconnected')));
            } : null,
            child: Text('Disconnect'),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.teal[700]),
          ),
        ],
      ),
    );
  }
}