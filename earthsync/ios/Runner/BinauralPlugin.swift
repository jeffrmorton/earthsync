import Flutter
import UIKit
import AVFoundation

@objc class BinauralPlugin: NSObject, FlutterPlugin {
    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "earthsync/binaural", binaryMessenger: registrar.messenger())
        let instance = BinauralPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    private var engine: AVAudioEngine?
    private var leftNode: AVAudioPlayerNode?
    private var rightNode: AVAudioPlayerNode?
    private var equalizer: AVAudioUnitEQ?
    private var volume: Float = 1.0

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "setFrequency":
            let frequency = call.arguments as? [String: Double] ?? ["frequency": 7.83]
            stopAudio()
            startAudio(frequency: frequency["frequency"]!)
            result(nil)
        case "setVolume":
            volume = Float(call.arguments as? [String: Double] ?? ["volume": 1.0])["volume"]!.clamped(to: 0.0...1.0)
            leftNode?.volume = volume
            rightNode?.volume = volume
            result(nil)
        case "setBackground":
            // Background handled by just_audio_background
            result(nil)
        case "setEqualizer":
            let settings = call.arguments as? [String: Int] ?? ["bass": 50, "mid": 50, "treble": 50]
            configureEqualizer(bass: settings["bass"]!, mid: settings["mid"]!, treble: settings["treble"]!)
            result(nil)
        case "dispose":
            stopAudio()
            result(nil)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func startAudio(frequency: Double) {
        engine = AVAudioEngine()
        leftNode = AVAudioPlayerNode()
        rightNode = AVAudioPlayerNode()
        equalizer = AVAudioUnitEQ(numberOfBands: 3)

        let baseFreq = 200.0
        let sampleRate = 44100.0
        let bufferSize = 4096
        let leftBuffer = AVAudioPCMBuffer(pcmFormat: AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1)!, frameCapacity: UInt32(bufferSize))!
        let rightBuffer = AVAudioPCMBuffer(pcmFormat: AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1)!, frameCapacity: UInt32(bufferSize))!

        for i in 0..<bufferSize {
            let t = Double(i) / sampleRate
            leftBuffer.floatChannelData![0][i] = Float(sin(2 * Double.pi * baseFreq * t))
            rightBuffer.floatChannelData![0][i] = Float(sin(2 * Double.pi * (baseFreq + frequency) * t))
        }
        leftBuffer.frameLength = UInt32(bufferSize)
        rightBuffer.frameLength = UInt32(bufferSize)

        engine!.attach(leftNode!)
        engine!.attach(rightNode!)
        engine!.attach(equalizer!)
        engine!.connect(leftNode!, to: equalizer!, format: leftBuffer.format)
        engine!.connect(rightNode!, to: equalizer!, format: rightBuffer.format)
        engine!.connect(equalizer!, to: engine!.mainMixerNode, format: leftBuffer.format)

        try! engine!.start()
        leftNode!.volume = volume
        rightNode!.volume = volume
        leftNode!.play()
        rightNode!.play()

        leftNode!.scheduleBuffer(leftBuffer, at: nil, options: .loops)
        rightNode!.scheduleBuffer(rightBuffer, at: nil, options: .loops)
    }

    private func configureEqualizer(bass: Int, mid: Int, treble: Int) {
        equalizer?.bands[0].gain = Float(bass - 50) // Bass
        equalizer?.bands[1].gain = Float(mid - 50)   // Mid
        equalizer?.bands[2].gain = Float(treble - 50) // Treble
    }

    private func stopAudio() {
        leftNode?.stop()
        rightNode?.stop()
        engine?.stop()
        engine = nil
        leftNode = nil
        rightNode = nil
        equalizer = nil
    }
}

extension Comparable {
    func clamped(to limits: ClosedRange<Self>) -> Self {
        return min(max(self, limits.lowerBound), limits.upperBound)
    }
}