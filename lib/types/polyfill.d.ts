/**
 * Browser-side fallback for a secure-context API.
 *
 * The UI is commonly opened over plain http on a LAN address, which is not a
 * secure context, so crypto.randomUUID is missing there. The transform is
 * idempotent and only touches the harness index document.
 */
/** Insert the polyfill once, before the closing head tag. */
export declare function injectPolyfill(htmlText: string): string;
