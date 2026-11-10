/**
 * Browser-side fallback for a secure-context API.
 *
 * The UI is commonly opened over plain http on a LAN address, which is not a
 * secure context, so crypto.randomUUID is missing there. The transform is
 * idempotent and only touches the harness index document.
 */

const POLYFILL =
  '<script data-dsh-frontgate>(function(){var c=globalThis.crypto;if(!c||typeof c.randomUUID==="function")return;c.randomUUID=function(){var b=c.getRandomValues(new Uint8Array(16));b[6]=b[6]&15|64;b[8]=b[8]&63|128;var s="";for(var i=0;i<16;i++)s+=(b[i]+256).toString(16).slice(1);return s.slice(0,8)+"-"+s.slice(8,12)+"-"+s.slice(12,16)+"-"+s.slice(16,20)+"-"+s.slice(20)}})();</script>'

/** Insert the polyfill once, before the closing head tag. */
export function injectPolyfill(htmlText: string): string {
  if (typeof htmlText !== 'string' || htmlText.includes('data-dsh-frontgate')) return htmlText
  const at = htmlText.indexOf('</head>')
  return at === -1 ? htmlText : htmlText.slice(0, at) + POLYFILL + htmlText.slice(at)
}
