//! The HTML page rendered at the end of an OAuth round-trip.

use bytes::Bytes;
use http::{StatusCode, header};
use http_body_util::Full;
use serde::Serialize;
use serde_json::json;

use crate::authorization::Authorization;
use crate::response::{Response, write_json};

impl Authorization {
    /// Renders a small HTML page that persists the token response in
    /// `localStorage` under `authorization-storage` (matching the frontend
    /// zustand persist format) and either notifies the opener (popup flow) or
    /// redirects to the saved redirect URL (redirect flow).
    pub fn render_callback_page<T: Serialize>(&self, data: T) -> Response {
        let json_data = match serde_json::to_string(&data) {
            Ok(json_data) => escape_for_script(&json_data),
            Err(_) => {
                return write_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "message": "Failed to encode token response", "code": "ERROR" }),
                );
            }
        };

        let global_options = format!(
            r#"<script id="__GLOBAL_DATA__" data-app="" type="application/json">{json_data}</script>"#
        );
        let html = TOKEN_CALLBACK_HTML
            .replace("{{.title}}", "Signing in…")
            .replace("{{.globalOptions}}", &global_options);

        http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::from(html)))
            .expect("callback page response is valid")
    }
}

/// Escapes the characters that could terminate the surrounding `<script>` tag.
/// The replacements are valid JSON escapes, so the payload still parses.
fn escape_for_script(json: &str) -> String {
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

const TOKEN_CALLBACK_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{{.title}}</title>
<style>
  body{display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;font-family:system-ui,sans-serif;color-scheme:light dark}
  .panel{display:flex;flex-direction:column;align-items:center;gap:12px;max-width:28rem;padding:0 16px;text-align:center}
  .status{display:flex;align-items:center;color:#52525b}
  .status.is-hidden{display:none}
  .spinner{width:24px;height:24px;border:3px solid #8883;border-top-color:#666;border-radius:50%;animation:spin .6s linear infinite;margin-right:12px}
  @keyframes spin{to{transform:rotate(360deg)}}
  #message{margin:0;padding:12px 16px;border-radius:10px;font-size:15px;line-height:1.5;font-weight:500}
  #message.is-error{color:#991b1b;background:#fef2f2;border:1px solid #fecaca}
  #message.is-success{color:#166534;background:#f0fdf4;border:1px solid #bbf7d0}
  .back-btn{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 16px;border:1px solid #d4d4d8;border-radius:8px;background:#fff;color:#18181b;font-family:inherit;font-size:14px;font-weight:500;text-decoration:none;cursor:pointer}
  .back-btn:hover{background:#f4f4f5}
  .close-btn{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 16px;border:1px solid #d4d4d8;border-radius:8px;background:#fff;color:#18181b;font-family:inherit;font-size:14px;font-weight:500;cursor:pointer}
  .close-btn:hover{background:#f4f4f5}
  @media (prefers-color-scheme:dark){
    .status{color:#a1a1aa}
    #message.is-error{color:#fecaca;background:#450a0a;border-color:#7f1d1d}
    #message.is-success{color:#bbf7d0;background:#052e16;border-color:#166534}
    .back-btn{border-color:#3f3f46;background:#18181b;color:#fafafa}
    .back-btn:hover{background:#27272a}
    .close-btn{border-color:#3f3f46;background:#18181b;color:#fafafa}
    .close-btn:hover{background:#27272a}
  }
</style>
{{.globalOptions}}
</head>
<body>
<div class="panel">
  <div id="status" class="status"><div class="spinner"></div>Completing sign-in…</div>
  <p id="message"></p>
  <button id="back-to-sign-in" type="button" class="back-btn" hidden>Back to sign in</button>
  <button id="close-tab" type="button" class="close-btn" hidden>Close this tab</button>
</div>

<script>
function getGlobalOptionsJson() {
    const el = document.getElementById('__GLOBAL_DATA__');
    if (!el) return {};
    try {
        return JSON.parse(el.textContent || '{}')
    } catch {
        return {}
    }
}
const globalOptions = getGlobalOptionsJson();
const statusEl = document.getElementById('status');
const messageEl = document.getElementById('message');
const backToSignInEl = document.getElementById('back-to-sign-in');
const closeTabEl = document.getElementById('close-tab');

function closeCurrentTab() {
	if (window.opener && !window.opener.closed) {
		try {
			window.close();
		} catch (_) {}
	}
	if (!window.closed) {
		window.close();
	}
}

if (closeTabEl) {
	closeTabEl.addEventListener('click', closeCurrentTab);
}

function redirectTo(url) {
	window.location.replace(url);
}

if (backToSignInEl) {
	backToSignInEl.addEventListener('click', function () {
		redirectTo('/sign-in');
	});
}

function showError(message) {
	if (statusEl) statusEl.classList.add('is-hidden');
	if (messageEl) {
		messageEl.textContent = message || 'Sign-in failed';
		messageEl.className = 'is-error';
		messageEl.hidden = false;
	}
	if (backToSignInEl) backToSignInEl.hidden = Boolean(globalOptions?.user);
}

function showSuccess(message, options) {
	const opts = options || {};
	if (statusEl) statusEl.classList.add('is-hidden');
	if (messageEl) {
		messageEl.textContent = message || 'Signed in successfully. Redirecting…';
		messageEl.className = 'is-success';
		messageEl.hidden = false;
	}
	if (backToSignInEl) backToSignInEl.hidden = true;
	if (closeTabEl) closeTabEl.hidden = !opts.showCloseTab;
}

const AUTH_STORAGE_KEY = 'authorization-storage';

function resolveSessionId(user, sessionId) {
	if (sessionId) return sessionId;
	if (user && user.id) return user.id;
	if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
	return 'session-' + Date.now();
}

function parsePersistedSnapshot(raw) {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw);
		if (parsed && typeof parsed === 'object' && parsed.state && typeof parsed.state === 'object') {
			return parsed.state;
		}
		if (parsed && typeof parsed === 'object' && Array.isArray(parsed.sessions)) {
			return parsed;
		}
		return null;
	} catch {
		return null;
	}
}

function persistSignIn({ session_id, user, tokens, trusted }) {
	const existing = parsePersistedSnapshot(localStorage.getItem(AUTH_STORAGE_KEY)) || {
		sessions: [],
		current_session: '',
		redirectUrl: ''
	};
	const id = resolveSessionId(user, session_id);
	const sessions = [
		...existing.sessions.filter(function (session) { return session.session_id !== id; }),
		{
			session_id: id,
			user: { id: user.id, ...user },
			tokens: {
				access_token: tokens.access_token,
				refresh_token: tokens.refresh_token
			},
			trusted: Boolean(trusted)
		}
	];
	const snapshot = {
		sessions: sessions,
		current_session: id,
		redirectUrl: existing.redirectUrl || ''
	};
	localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(snapshot));
	return snapshot;
}

function finishSignIn(snapshot, message) {
	const redirectTarget = snapshot.redirectUrl || '/';
	const successMessage = message || 'Signed in successfully. Redirecting…';

	showSuccess(successMessage);

	window.setTimeout(function () {
		if (window.opener && !window.opener.closed) {
			try {
				window.opener.postMessage(
					{ type: 'authorization-sign-in', session_id: snapshot.current_session },
					window.location.origin
				);
			} catch (_) {}
			window.close();
			return;
		}
		redirectTo(redirectTarget);
	}, 900);
}

function finishConnect(message, resourceId) {
	const successMessage = message || 'Microsoft account connected successfully.';

	showSuccess(successMessage, { showCloseTab: true });

	if (window.opener && !window.opener.closed) {
		try {
			window.opener.postMessage(
				{ type: 'microsoft-connect-completed', resource_id: resourceId || '' },
				window.location.origin
			);
		} catch (_) {}
	}
}

if (globalOptions?.code === 'ERROR') {
	showError(globalOptions?.message);
} else if (globalOptions?.type === "sign_in") {
	if (globalOptions?.user && globalOptions?.tokens) {
		const snapshot = persistSignIn({
			session_id: globalOptions.session_id,
			user: globalOptions.user,
			tokens: globalOptions.tokens,
			trusted: globalOptions.trusted
		});
		finishSignIn(snapshot, globalOptions?.message);
	} else {
		showError('Failed to sign in, no user or tokens found');
	}
} else if (globalOptions?.type === 'connect' && globalOptions?.code === 'SUCCESS') {
	finishConnect(globalOptions?.message, globalOptions?.resource_id);
} else if (globalOptions?.type === "get_session") {
	showError('Not implemented');
}


</script>
</body>
</html>"#;
