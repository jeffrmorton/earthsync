import Globe from 'react-globe.gl';
import { useRef, useEffect } from 'react';

interface GlobeStation {
  id: string;
  lat: number;
  lng: number;
  active: boolean;
}

interface StationGlobeProps {
  stations: GlobeStation[];
  selectedStation: string | null;
  onSelect: (id: string) => void;
  width?: number;
  height?: number;
}

export function StationGlobe({
  stations,
  selectedStation,
  onSelect,
  width = 300,
  height = 250,
}: StationGlobeProps) {
  const globeEl = useRef<{ pointOfView: (coords: object) => void } | undefined>(undefined);

  const pointsData = stations.map((s) => ({
    lat: s.lat,
    lng: s.lng,
    size: s.id === selectedStation ? 0.8 : 0.4,
    color: s.active ? '#4ade80' : '#f87171',
    label: s.id,
    stationId: s.id,
  }));

  useEffect(() => {
    if (globeEl.current && stations.length > 0) {
      const first = stations[0];
      globeEl.current.pointOfView({ lat: first.lat, lng: first.lng, altitude: 2.5 });
    }
  }, [stations]);

  return (
    <div data-testid="station-globe">
      <Globe
        ref={globeEl as never}
        width={width}
        height={height}
        backgroundColor="rgba(0,0,0,0)"
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
        pointsData={pointsData}
        pointAltitude={0.01}
        pointRadius="size"
        pointColor="color"
        pointLabel="label"
        onPointClick={(point: object) => {
          const p = point as Record<string, unknown>;
          if (p.stationId) onSelect(p.stationId as string);
        }}
      />
    </div>
  );
}
