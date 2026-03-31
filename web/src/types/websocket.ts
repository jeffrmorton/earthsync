import type { Location } from './station';

export interface LorentzianMode {
  freq: number;
  amp: number;
  qFactor: number;
  freqErr: number | null;
  ampErr: number | null;
  qErr: number | null;
}

export interface LorentzianFitResult {
  modes: LorentzianMode[];
  background: { slope: number; intercept: number };
  chiSquared: number | null;
  degreesOfFreedom: number;
  converged: boolean;
}

export interface TrackedPeak {
  freq: number;
  amp: number;
  qFactor: number | null;
  freqErr: number | null;
  ampErr: number | null;
  qErr: number | null;
  snr: number | null;
  trackStatus: 'new' | 'continuing';
  trackId: string;
}

export interface NoiseFloor {
  median: number;
  std: number;
}

export interface TransientInfo {
  type: 'none' | 'broadband' | 'narrowband' | 'error';
  details: string | null;
}

export interface WSPayload {
  stationId: string;
  timestamp: string;
  location: Location;
  spectrogram: number[];
  lorentzianFit: LorentzianFitResult | null;
  detectedPeaks: TrackedPeak[];
  transientInfo: TransientInfo;
  noiseFloor: NoiseFloor | null;
  qualityFlags: string[];
  algorithmVersion: string;
  calibrationStatus: string;
  sampleRateHz: number;
  frequencyResolutionHz: number | null;
}
