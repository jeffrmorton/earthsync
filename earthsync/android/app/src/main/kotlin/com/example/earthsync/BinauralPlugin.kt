package com.example.earthsync

import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import android.media.audiofx.Equalizer
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlin.math.sin

class BinauralPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel
    private var leftTrack: AudioTrack? = null
    private var rightTrack: AudioTrack? = null
    private var equalizer: Equalizer? = null
    private val sampleRate = 44100
    private val bufferSize = AudioTrack.getMinBufferSize(sampleRate, AudioFormat.CHANNEL_OUT_STEREO, AudioFormat.ENCODING_PCM_16BIT)
    private var volume = 1.0f

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "earthsync/binaural")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "setFrequency" -> {
                val frequency = call.argument<Double>("frequency") ?: 7.83
                stopTracks()
                startTracks(frequency)
                result.success(null)
            }
            "setVolume" -> {
                volume = (call.argument<Double>("volume") ?: 1.0).toFloat().coerceIn(0.0f, 1.0f)
                leftTrack?.setVolume(volume)
                rightTrack?.setVolume(volume)
                result.success(null)
            }
            "setBackground" -> {
                // Background handling managed by just_audio_background
                result.success(null)
            }
            "setEqualizer" -> {
                val settings = call.arguments as Map<String, Int>
                val bass = settings["bass"] ?: 50
                val mid = settings["mid"] ?: 50
                val treble = settings["treble"] ?: 50
                configureEqualizer(bass, mid, treble)
                result.success(null)
            }
            "dispose" -> {
                stopTracks()
                equalizer?.release()
                equalizer = null
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun startTracks(frequency: Double) {
        val baseFreq = 200.0
        leftTrack = createTrack(baseFreq)
        rightTrack = createTrack(baseFreq + frequency)
        leftTrack?.setVolume(volume)
        rightTrack?.setVolume(volume)
        equalizer = Equalizer(0, leftTrack!!.audioSessionId).apply { enabled = true }
        leftTrack?.play()
        rightTrack?.play()
    }

    private fun createTrack(freq: Double): AudioTrack {
        val track = AudioTrack(
            AudioManager.STREAM_MUSIC, sampleRate, AudioFormat.CHANNEL_OUT_MONO,
            AudioFormat.ENCODING_PCM_16BIT, bufferSize, AudioTrack.MODE_STREAM
        )
        val buffer = ShortArray(bufferSize)
        Thread {
            var t = 0.0
            while (track.state == AudioTrack.STATE_INITIALIZED) {
                for (i in buffer.indices) {
                    buffer[i] = (sin(2 * Math.PI * freq * t / sampleRate) * Short.MAX_VALUE).toInt().toShort()
                    t += 1.0
                }
                track.write(buffer, 0, buffer.size)
            }
        }.start()
        return track
    }

    private fun configureEqualizer(bass: Int, mid: Int, treble: Int) {
        equalizer?.let {
            val bands = it.numberOfBands
            for (i in 0 until bands) {
                val level = when (i) {
                    0 -> bass - 50 // Bass band
                    1 -> mid - 50  // Mid band
                    else -> treble - 50 // Treble band
                }
                it.setBandLevel(i.toShort(), (level * 100).toShort()) // Scale to -5000 to 5000
            }
        }
    }

    private fun stopTracks() {
        leftTrack?.stop()
        leftTrack?.release()
        rightTrack?.stop()
        rightTrack?.release()
        leftTrack = null
        rightTrack = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        stopTracks()
    }
}