import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DashboardLayout } from './DashboardLayout';

describe('DashboardLayout', () => {
  it('renders the layout container', () => {
    render(
      <DashboardLayout
        spectrogram={<div>spec</div>}
        psd={<div>psd</div>}
        peaks={<div>peaks</div>}
        globe={<div>globe</div>}
        quality={<div>quality</div>}
      />,
    );
    expect(screen.getByTestId('dashboard-layout')).toBeDefined();
  });

  it('renders all panel content', () => {
    render(
      <DashboardLayout
        spectrogram={<div data-testid="spec-slot">Spectrogram</div>}
        psd={<div data-testid="psd-slot">PSD</div>}
        peaks={<div data-testid="peaks-slot">Peaks</div>}
        globe={<div data-testid="globe-slot">Globe</div>}
        quality={<div data-testid="quality-slot">Quality</div>}
      />,
    );
    expect(screen.getByTestId('spec-slot')).toBeDefined();
    expect(screen.getByTestId('psd-slot')).toBeDefined();
    expect(screen.getByTestId('peaks-slot')).toBeDefined();
    expect(screen.getByTestId('globe-slot')).toBeDefined();
    expect(screen.getByTestId('quality-slot')).toBeDefined();
  });

  it('renders content text in correct panels', () => {
    render(
      <DashboardLayout
        spectrogram={<span>Spectrogram Content</span>}
        psd={<span>PSD Content</span>}
        peaks={<span>Peaks Content</span>}
        globe={<span>Globe Content</span>}
        quality={<span>Quality Content</span>}
      />,
    );
    const layout = screen.getByTestId('dashboard-layout');
    expect(layout.textContent).toContain('Spectrogram Content');
    expect(layout.textContent).toContain('PSD Content');
    expect(layout.textContent).toContain('Peaks Content');
    expect(layout.textContent).toContain('Globe Content');
    expect(layout.textContent).toContain('Quality Content');
  });

  it('has grid layout classes', () => {
    render(
      <DashboardLayout
        spectrogram={<div>s</div>}
        psd={<div>p</div>}
        peaks={<div>pk</div>}
        globe={<div>g</div>}
        quality={<div>q</div>}
      />,
    );
    const layout = screen.getByTestId('dashboard-layout');
    expect(layout.className).toContain('grid');
  });
});
