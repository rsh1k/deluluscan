import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './main.css';

// Dev only: hand App a fixture so `npm run dev` renders without a generated
// payload. `import.meta.env.DEV` is statically false in a build, so both this
// import and the fixture are tree-shaken out of the shipped bundle.
if (import.meta.env.DEV) {
  const { devScans } = await import('./data/dev-scan');
  (globalThis as { __DELULUSCAN_DEV__?: unknown }).__DELULUSCAN_DEV__ = devScans;
}

const container = document.getElementById('root');
if (!container) throw new Error('root element missing');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
