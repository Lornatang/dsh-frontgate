/**
 * The only HTML page the gate serves itself: the login form.
 *
 * It is inline-styled and script-free so that a strict CSP can be applied.
 */
import { escapeHtml, LOGIN_REFERRER_POLICY } from './http.ts'

/** Render the login page for a given title, post-login path and error message. */
export function loginPage(title: string, next: string, error: string): string {
  const action = '/__gate/login?next=' + encodeURIComponent(next)
  const message = error ? '<p class="err">' + escapeHtml(error) + '</p>' : ''
  return [
    '<!doctype html>',
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="referrer" content="' + LOGIN_REFERRER_POLICY + '">',
    '<title>' + escapeHtml(title) + ' - Sign in</title>',
    '<style>',
    '  :root{color-scheme:dark}',
    '  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e1014;color:#e6e8ee;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}',
    '  form{width:min(360px,calc(100vw - 48px));padding:28px 26px 24px;border:1px solid #262b36;border-radius:14px;background:#151922;box-shadow:0 20px 60px rgba(0,0,0,.45)}',
    '  h1{margin:0 0 6px;font-size:16px;font-weight:600}',
    '  p{margin:0 0 18px;color:#8b93a5;font-size:12.5px}',
    '  .err{padding:9px 11px;margin:0 0 14px;border-radius:8px;background:rgba(240,92,92,.12);border:1px solid rgba(240,92,92,.3);color:#ff9b9b}',
    '  input{width:100%;box-sizing:border-box;padding:10px 12px;margin:0 0 14px;border-radius:9px;border:1px solid #2c3341;background:#0f131a;color:inherit;font:inherit;outline:none}',
    '  input:focus{border-color:#3f6df0;box-shadow:0 0 0 3px rgba(63,109,240,.18)}',
    '  button{width:100%;padding:10px 12px;border:0;border-radius:9px;background:#3f6df0;color:#fff;font:inherit;font-weight:600;cursor:pointer}',
    '  button:hover{background:#4b78ff}',
    '</style></head>',
    '<body>',
    '<form method="post" action="' + action + '">',
    '  <h1>' + escapeHtml(title) + '</h1>',
    '  <p>This instance is protected by a password gate. Enter the access password.</p>',
    '  ' + message,
    '  <input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password">',
    '  <button type="submit">Sign in</button>',
    '</form>',
    '</body></html>',
  ].join('\n')
}
