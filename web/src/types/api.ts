export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expiresIn: number;
}

export interface RegisterRequest {
  username: string;
  password: string;
}

export interface IngestRequest {
  stationId: string;
  timestamp: string;
  location: { lat: number; lon: number };
  samples: number[];
  sampleRateHz: number;
  segmentDurationS: number;
  sensorType?: string;
  metadata?: Record<string, unknown>;
}

export interface HistoryDataPoint {
  ts: number;
  spectrogram: number[];
  transientInfo: { type: string; details: string | null };
}

export interface HistoryResponse {
  stationId: string;
  location: { lat: number; lon: number };
  dataPoints: HistoryDataPoint[];
}

export interface PeakHistoryEntry {
  ts: number;
  peaks: {
    freq: number;
    amp: number;
    qFactor: number | null;
    trackStatus: string;
    trackId: string;
    freqErr: number | null;
    ampErr: number | null;
    qErr: number | null;
    snr: number | null;
  }[];
}

export interface PeakHistoryResponse {
  stationId: string;
  peaks: PeakHistoryEntry[];
}
