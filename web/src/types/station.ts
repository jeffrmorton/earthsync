export interface Location {
  lat: number;
  lon: number;
}

export interface StationMeta {
  id: string;
  location: Location;
  lastUpdate: number;
  noiseFloor: { median: number; std: number } | null;
  algorithmVersion: string;
  calibrationStatus: 'calibrated' | 'uncalibrated';
  qualityFlags: string[];
  sampleRateHz: number;
  frequencyResolutionHz: number | null;
}
