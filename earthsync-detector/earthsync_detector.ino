#include <SPI.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoFFT.h>
#include <SD.h>

// Pin definitions
#define ADC_CS 5
#define SD_CS 15

// WiFi credentials
const char* ssid = "your-ssid";
const char* password = "your-password";

// Server API endpoint
const char* serverUrl = "https://your-server.com/schumann-frequency"; // Replace with actual URL
const char* apiKey = "your-api-key"; // Replace with actual API key

// FFT parameters
#define SAMPLES 256
#define SAMPLING_FREQ 256
double vReal[SAMPLES];
double vImag[SAMPLES];
ArduinoFFT FFT = ArduinoFFT();

// ADC setup
SPISettings spiSettings(2000000, MSBFIRST, SPI_MODE0);

void setup() {
  Serial.begin(115200);
  SPI.begin();
  pinMode(ADC_CS, OUTPUT);
  digitalWrite(ADC_CS, HIGH);

  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  // Initialize SD (optional)
  if (!SD.begin(SD_CS)) {
    Serial.println("SD card initialization failed");
  }
}

void loop() {
  // Sample ADC
  for (int i = 0; i < SAMPLES; i++) {
    digitalWrite(ADC_CS, LOW);
    SPI.beginTransaction(spiSettings);
    byte highByte = SPI.transfer(0xFF);
    byte lowByte = SPI.transfer(0xFF);
    SPI.endTransaction();
    digitalWrite(ADC_CS, HIGH);
    int16_t sample = (highByte << 8) | lowByte; // Simplified 16-bit read
    vReal[i] = (double)sample * (5.0 / 65536.0); // Convert to voltage
    vImag[i] = 0.0;
    delayMicroseconds(3906); // 256 Hz = 3906 µs/sample
  }

  // Perform FFT
  FFT.Windowing(vReal, SAMPLES, FFT_WIN_TYP_HAMMING, FFT_FORWARD);
  FFT.Compute(vReal, vImag, SAMPLES, FFT_FORWARD);
  FFT.ComplexToMagnitude(vReal, vImag, SAMPLES);

  // Find dominant frequency (between 3-50 Hz)
  double maxMagnitude = 0.0;
  double dominantFreq = 0.0;
  for (int i = 1; i < SAMPLES / 2; i++) { // Skip DC (i=0)
    double freq = i * (SAMPLING_FREQ / SAMPLES);
    if (freq >= 3 && freq <= 50 && vReal[i] > maxMagnitude) {
      maxMagnitude = vReal[i];
      dominantFreq = freq;
    }
  }

  // Update database
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(serverUrl);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-api-key", apiKey);
    String json = "{\"frequency\":" + String(dominantFreq, 2) + ",\"timestamp\":\"" + String(millis()) + "\"}";
    int httpCode = http.POST(json);
    if (httpCode > 0) {
      Serial.println("Database updated: " + String(httpCode));
    } else {
      Serial.println("HTTP error: " + http.getString());
    }
    http.end();
  }

  // Optional: Log to SD
  File dataFile = SD.open("/freq.txt", FILE_APPEND);
  if (dataFile) {
    dataFile.println(String(dominantFreq, 2) + "," + String(millis()));
    dataFile.close();
  }

  delay(60000); // Update every minute
}