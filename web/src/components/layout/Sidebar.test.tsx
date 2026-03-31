import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Sidebar } from './Sidebar';

const mockStations = [
  { id: 'sierra-nevada', location: { lat: 37.0, lon: -3.4 } },
  { id: 'modra', location: { lat: 48.4, lon: 17.3 } },
];

describe('Sidebar', () => {
  it('renders the sidebar container', () => {
    render(
      <Sidebar
        stations={[]}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    expect(screen.getByTestId('sidebar')).toBeDefined();
  });

  it('renders Stations heading', () => {
    render(
      <Sidebar
        stations={[]}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    expect(screen.getByTestId('sidebar').textContent).toContain('Stations');
  });

  it('renders All Stations button', () => {
    render(
      <Sidebar
        stations={[]}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    const btn = screen.getByTestId('station-all');
    expect(btn).toBeDefined();
    expect(btn.textContent).toBe('All Stations');
  });

  it('renders station list', () => {
    render(
      <Sidebar
        stations={mockStations}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    expect(screen.getByTestId('station-sierra-nevada')).toBeDefined();
    expect(screen.getByTestId('station-modra')).toBeDefined();
  });

  it('displays station coordinates', () => {
    render(
      <Sidebar
        stations={mockStations}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    const sn = screen.getByTestId('station-sierra-nevada');
    expect(sn.textContent).toContain('37.0');
    expect(sn.textContent).toContain('-3.4');
  });

  it('calls onSelectStation with null when All Stations clicked', () => {
    const handler = vi.fn();
    render(
      <Sidebar
        stations={mockStations}
        selectedStation="sierra-nevada"
        onSelectStation={handler}
      />,
    );
    fireEvent.click(screen.getByTestId('station-all'));
    expect(handler).toHaveBeenCalledWith(null);
  });

  it('calls onSelectStation with station id when station clicked', () => {
    const handler = vi.fn();
    render(
      <Sidebar
        stations={mockStations}
        selectedStation={null}
        onSelectStation={handler}
      />,
    );
    fireEvent.click(screen.getByTestId('station-modra'));
    expect(handler).toHaveBeenCalledWith('modra');
  });

  it('highlights selected station', () => {
    const { container } = render(
      <Sidebar
        stations={mockStations}
        selectedStation="sierra-nevada"
        onSelectStation={vi.fn()}
      />,
    );
    const selectedBtn = screen.getByTestId('station-sierra-nevada');
    expect(selectedBtn.className).toContain('bg-bg-hover');
    expect(selectedBtn.className).toContain('text-text-primary');
    // All Stations should NOT be highlighted when a station is selected
    const allBtn = screen.getByTestId('station-all');
    expect(allBtn.className).toContain('text-text-secondary');
  });

  it('highlights All Stations when selectedStation is null', () => {
    render(
      <Sidebar
        stations={mockStations}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    const allBtn = screen.getByTestId('station-all');
    expect(allBtn.className).toContain('bg-bg-hover');
    expect(allBtn.className).toContain('text-text-primary');
  });

  it('renders empty station list', () => {
    render(
      <Sidebar
        stations={[]}
        selectedStation={null}
        onSelectStation={vi.fn()}
      />,
    );
    // Only All Stations button should exist
    expect(screen.getByTestId('station-all')).toBeDefined();
  });
});
