import { forwardRef } from 'react';

const Globe = forwardRef(function MockGlobe(props: Record<string, unknown>, _ref) {
  return <div data-testid="mock-globe" {...(props as object)} />;
});

export default Globe;
