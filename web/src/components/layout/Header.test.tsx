import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Header } from './Header';

describe('Header', () => {
  it('renders the title and subtitle', () => {
    render(<Header connected={false} stationCount={0} />);
    const header = screen.getByTestId('header');
    expect(header).toBeDefined();
    expect(header.textContent).toContain('EarthSync');
    expect(header.textContent).toContain('Schumann Resonance Monitor');
  });

  it('shows Connected status when connected', () => {
    render(<Header connected={true} stationCount={0} />);
    expect(screen.getByTestId('header').textContent).toContain('Connected');
  });

  it('shows Disconnected status when not connected', () => {
    render(<Header connected={false} stationCount={0} />);
    expect(screen.getByTestId('header').textContent).toContain('Disconnected');
  });

  it('shows green indicator when connected', () => {
    const { container } = render(
      <Header connected={true} stationCount={0} />,
    );
    const dot = container.querySelector('.bg-accent-green');
    expect(dot).toBeDefined();
  });

  it('shows red indicator when disconnected', () => {
    const { container } = render(
      <Header connected={false} stationCount={0} />,
    );
    const dot = container.querySelector('.bg-accent-red');
    expect(dot).toBeDefined();
  });

  it('displays station count with plural', () => {
    render(<Header connected={false} stationCount={3} />);
    expect(screen.getByTestId('header').textContent).toContain('3 stations');
  });

  it('displays station count singular for 1', () => {
    render(<Header connected={false} stationCount={1} />);
    expect(screen.getByTestId('header').textContent).toContain('1 station');
    expect(screen.getByTestId('header').textContent).not.toContain(
      '1 stations',
    );
  });

  it('displays station count 0 with plural', () => {
    render(<Header connected={false} stationCount={0} />);
    expect(screen.getByTestId('header').textContent).toContain('0 stations');
  });

  it('renders theme toggle button when onToggleTheme provided', () => {
    const toggle = vi.fn();
    render(
      <Header connected={false} stationCount={0} onToggleTheme={toggle} />,
    );
    const btn = screen.getByTestId('theme-toggle');
    expect(btn).toBeDefined();
    expect(btn.textContent).toBe('Theme');
  });

  it('calls onToggleTheme when theme button clicked', () => {
    const toggle = vi.fn();
    render(
      <Header connected={false} stationCount={0} onToggleTheme={toggle} />,
    );
    fireEvent.click(screen.getByTestId('theme-toggle'));
    expect(toggle).toHaveBeenCalledTimes(1);
  });

  it('does not render theme toggle when onToggleTheme is undefined', () => {
    render(<Header connected={false} stationCount={0} />);
    expect(screen.queryByTestId('theme-toggle')).toBeNull();
  });

  it('renders Q-burst indicator when activeQBurst is provided', () => {
    render(
      <Header
        connected={true}
        stationCount={1}
        activeQBurst={{ stationId: 'sim1', details: 'Q-burst detected' }}
      />,
    );
    const indicator = screen.getByTestId('qburst-indicator');
    expect(indicator).toBeDefined();
    expect(indicator.textContent).toContain('Q-BURST');
    expect(indicator.textContent).toContain('sim1');
  });

  it('does not render Q-burst indicator when activeQBurst is null', () => {
    render(<Header connected={true} stationCount={1} activeQBurst={null} />);
    expect(screen.queryByTestId('qburst-indicator')).toBeNull();
  });

  it('does not render Q-burst indicator when activeQBurst is undefined', () => {
    render(<Header connected={true} stationCount={1} />);
    expect(screen.queryByTestId('qburst-indicator')).toBeNull();
  });
});
