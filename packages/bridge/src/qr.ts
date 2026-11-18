// Safety-number QR codes. Rendered locally: the approval page inlines the SVG
// and the CLI prints Unicode blocks. Nothing is fetched.

import { renderSVG, renderUnicodeCompact } from 'uqr';

export function qrTerminal(payload: string): string {
  return renderUnicodeCompact(payload, { border: 1, ecc: 'M' });
}

export function qrSvg(payload: string): string {
  const svg = renderSVG(payload, { border: 1, ecc: 'M', pixelSize: 4 });
  const start = svg.indexOf('<svg');
  const body = start >= 0 ? svg.slice(start) : svg;
  // The SVG namespace is a declaration, not a request. Anything else is a fetch.
  const withoutNamespace = body.replaceAll('xmlns="http://www.w3.org/2000/svg"', '');
  if (withoutNamespace.includes('<script') || withoutNamespace.includes('http://') || withoutNamespace.includes('https://')) {
    throw new Error('QR SVG must not reference external content');
  }
  return body;
}
