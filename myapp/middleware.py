import time
from django.core.cache import cache
from django.contrib.auth import logout
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .models import User_data, Dos_detection_table


def render_dos_blocked_page(title, message, incident_code="ERR_SEC_DOS_403"):
    """ShieldNet SOC Themed 403 Forbidden Quarantine Page with Auto-Logout Button"""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 Security Quarantine - ShieldNet</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Roboto, -apple-system, sans-serif; }}
            body {{
                background-color: #07090e;
                color: #f1f5f9;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
                overflow: hidden;
            }}
            body::before {{
                content: '';
                position: absolute;
                width: 450px;
                height: 450px;
                background: radial-gradient(circle, rgba(239, 68, 68, 0.15) 0%, rgba(7, 9, 14, 0) 70%);
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                z-index: 0;
            }}
            .card {{
                position: relative;
                z-index: 1;
                background: #0f1420;
                border: 1px solid rgba(239, 68, 68, 0.35);
                border-radius: 14px;
                padding: 40px 32px;
                width: 100%;
                max-width: 540px;
                text-align: center;
                box-shadow: 0 20px 45px rgba(0, 0, 0, 0.7), 0 0 25px rgba(239, 68, 68, 0.1);
            }}
            .shield-icon {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 72px;
                height: 72px;
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                border-radius: 50%;
                margin-bottom: 20px;
            }}
            .badge {{
                display: inline-block;
                background: rgba(239, 68, 68, 0.15);
                color: #ef4444;
                border: 1px solid rgba(239, 68, 68, 0.4);
                padding: 4px 14px;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: 700;
                letter-spacing: 1.5px;
                text-transform: uppercase;
                margin-bottom: 16px;
            }}
            h1 {{
                font-size: 1.45rem;
                font-weight: 800;
                color: #ffffff;
                letter-spacing: 0.5px;
                margin-bottom: 12px;
            }}
            p {{
                font-size: 0.88rem;
                color: #94a3b8;
                line-height: 1.6;
                margin-bottom: 25px;
            }}
            .incident-box {{
                background: #030407;
                border: 1px solid #1e293b;
                border-radius: 8px;
                padding: 14px;
                margin-bottom: 25px;
                font-family: 'Courier New', monospace;
                font-size: 0.8rem;
                color: #06b6d4;
                display: flex;
                justify-content: space-around;
            }}
            .incident-item span {{
                display: block;
                color: #64748b;
                font-size: 0.7rem;
                text-transform: uppercase;
                margin-bottom: 2px;
            }}
            .btn-group {{
                display: flex;
                gap: 12px;
                justify-content: center;
                flex-wrap: wrap;
            }}
            .btn {{
                display: inline-block;
                background: #1e293b;
                color: #f1f5f9;
                border: 1px solid #334155;
                padding: 10px 20px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 0.85rem;
                font-weight: 600;
                transition: all 0.2s ease;
            }}
            .btn:hover {{
                background: #334155;
                border-color: #06b6d4;
                color: #06b6d4;
            }}
            .btn-cyan {{
                background: #06b6d4;
                color: #020617;
                border: none;
            }}
            .btn-cyan:hover {{
                background: #22d3ee;
                color: #020617;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="shield-icon">
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
            </div>
            <div>
                <span class="badge">Session Terminated</span>
            </div>
            <h1>{title}</h1>
            <p>{message}</p>

            <div class="incident-box">
                <div class="incident-item">
                    <span>Incident Reference</span>
                    <strong>{incident_code}</strong>
                </div>
                <div class="incident-item">
                    <span>Active Session</span>
                    <strong style="color: #ef4444;">REVOKED</strong>
                </div>
            </div>

            <div class="btn-group">
                <a href="/myapp/login_page/#a" class="btn btn-cyan">Return to Login Page</a>
                <a href="mailto:admin@shieldnet.local" class="btn">Contact Administrator</a>
            </div>
        </div>
    </body>
    </html>
    """
    return HttpResponseForbidden(html_content)


class DosProtectionMiddleware(MiddlewareMixin):
    TIME_WINDOW = 10  # 10 Seconds
    THRESHOLD = 20  # Max Requests per Window

    # ഈ പാത്തുകൾക്ക് DoS മിഡിൽവെയർ ബ്ലോക്ക് ബാധകമാകില്ല
    EXEMPT_PATHS = [
        '/static/',
        '/media/',
        '/admin/',
        '/myapp/login_page/',
        '/myapp/logout_page/',
    ]

    def process_request(self, request):
        # 1. ലോഗിൻ, ലോഗൗട്ട്, സ്റ്റാറ്റിക് പാത്തുകൾ ഒഴിവാക്കുന്നു
        for path in self.EXEMPT_PATHS:
            if request.path.startswith(path):
                return None

        # 2. അഡ്മിൻ അല്ലെങ്കിൽ സ്റ്റാഫ് ആണെങ്കിൽ DoS ബ്ലോക്ക് ഒഴിവാക്കുന്നു
        if request.user.is_authenticated and (request.user.is_superuser or request.user.is_staff):
            return None

        user_data_obj = None

        if request.user.is_authenticated:
            try:
                user_data_obj = User_data.objects.get(LOGIN_id=request.user.id)
                # യൂസർ ഓൾറെഡി ബ്ലോക്ക് ആണെങ്കിൽ സെഷൻ ഉടൻ ഡിലീറ്റ് ചെയ്ത് ക്വാറന്റൈൻ പേജ് നൽകുന്നു
                if user_data_obj.status == 'blocked':
                    logout(request)
                    return render_dos_blocked_page(
                        title="Access Denied: Account Quarantined",
                        message="Your account has been quarantined due to high-frequency DoS request violations. Active session has been terminated.",
                        incident_code=f"USER_BLK_{user_data_obj.id}"
                    )
            except User_data.DoesNotExist:
                pass

        identifier = f"user_{user_data_obj.id}" if user_data_obj else f"ip_{request.META.get('REMOTE_ADDR')}"
        cache_key = f"dos_track_{identifier}"

        history = cache.get(cache_key, [])
        now = time.time()
        history = [t for t in history if now - t <= self.TIME_WINDOW]
        history.append(now)
        cache.set(cache_key, history, timeout=self.TIME_WINDOW + 2)

        # ത്രെഷോൾഡ് കവിഞ്ഞാൽ (DoS അറ്റാക്ക് നടന്നാൽ)
        if len(history) > self.THRESHOLD and user_data_obj:
            if user_data_obj.status != 'blocked':
                user_data_obj.status = 'blocked'
                user_data_obj.save()

                Dos_detection_table.objects.create(
                    USER=user_data_obj,
                    url=request.build_absolute_uri(),
                    confidence_score="98.5%",
                    prediction_result=f"High-frequency DoS anomaly: {len(history)} requests in {self.TIME_WINDOW}s window. User auto-blocked & logged out."
                )

            logout(request)

            return render_dos_blocked_page(
                title="Rate Limit Exceeded: DoS Block Triggered",
                message=f"Excessive request velocity detected ({len(history)} requests in {self.TIME_WINDOW}s). Your session has been revoked and the account is blocked.",
                incident_code="MITRE_T1499_DOS"
            )

        return None