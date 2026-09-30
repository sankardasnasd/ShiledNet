from django.contrib.auth.decorators import login_required
from myapp.models import *
from django.contrib.auth.models import User, Group
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from .middleware import render_dos_blocked_page

from django.shortcuts import render
from django.db.models import Q
import re



def public_home(request):
    total_scans = Network_Scan_table.objects.count()
    latest_scan = Network_Scan_table.objects.order_by('-timestamp').first()

    open_ports = "—"
    if latest_scan and latest_scan.scanresult:
        match = re.search(r'(\d+)\s*(?:open|ports?)', latest_scan.scanresult, re.I)
        open_ports = match.group(1) if match else "N/A"

    suspicious_count = Network_Scan_table.objects.filter(status__iexact='Suspicious').count()

    if latest_scan and latest_scan.status:
        network_status = latest_scan.status          # "Suspicious"
    else:
        network_status = "Clean"


    phishing_qs = PhishingDetection.objects.all()
    total_phishing = phishing_qs.count()
    phishing_count = phishing_qs.filter(result__iexact='PHISHING').count()
    legitimate_count = phishing_qs.filter(result__iexact='LEGITIMATE').count()

    latest_phish = phishing_qs.order_by('-created_at').first()
    if latest_phish and latest_phish.result:
        phishing_status = latest_phish.result.upper()   # PHISHING / LEGITIMATE
    else:
        phishing_status = "No Data"


    apk_qs = Apk_File_table.objects.all()
    total_apks = apk_qs.count()
    latest_apk = apk_qs.order_by('-timestamp').first()

    apk_verdict = "Safe"
    if latest_apk and latest_apk.prediction_result:
        pred = latest_apk.prediction_result.upper()
        if "CRITICAL MALWARE" in pred:
            apk_verdict = "Critical Malware"
        elif "SUSPICIOUS" in pred:
            apk_verdict = "Suspicious"

    dos_qs = Dos_detection_table.objects.all()
    total_dos = dos_qs.count()
    blocked = dos_qs.filter(
        Q(prediction_result__icontains='block') |
        Q(prediction_result__icontains='attack')
    ).count()

    if blocked > 0:
        request_rate_status = "Attack Detected"
    elif total_dos > 10:
        request_rate_status = "Elevated"
    else:
        request_rate_status = "Monitoring"

    context = {
        'open_ports': open_ports,
        'network_status': network_status,
        'suspicious_scans': suspicious_count,
        'phishing_status': phishing_status,
        'phishing_count': phishing_count,
        'legitimate_count': legitimate_count,
        'apk_verdict': apk_verdict,
        'request_rate_status': request_rate_status,
        'sandbox_status': 'Isolated',
        'total_scans': total_scans,
        'total_phishing': total_phishing,
        'total_apks': total_apks,
        'total_dos_alerts': total_dos,
    }
    return render(request, 'public page.html', context)




@csrf_exempt
def login_page(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.groups.filter(name='admin').exists():
                login(request, user)
                return redirect('/myapp/admin_home/')

            elif user.groups.filter(name='user').exists():
                try:
                    user_obj = User_data.objects.get(LOGIN=user)
                    if user_obj.status == 'blocked':
                        logout(request)
                        return render_dos_blocked_page(
                            title="Access Denied: Account Quarantined",
                            message="Your account is currently blocked due to suspected Denial-of-Service policy violations. Any active session has been revoked. Contact administrator to restore access.",
                            incident_code=f"LOGIN_BLOCKED_UID_{user_obj.id}"
                        )
                except User_data.DoesNotExist:
                    pass

                login(request, user)
                return redirect('/myapp/userhome/')

            else:
                messages.error(request, "Your account does not have an assigned role.")
                return redirect('/myapp/login_page/#a')

        else:
            messages.error(request, "Invalid username or password.")
            return redirect('/myapp/login_page/#a')

    return render(request, 'login page.html')


def user_register(request):

    if request.method == 'POST':

        name = request.POST['name']
        phone = request.POST['phone']
        Adress = request.POST['Adress']
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']


        if  User.objects.filter(username=username).exists():

            messages.error(
                request,
                "Username Already Exists."
            )

            return redirect('/myapp/user_register/#a')


        if  User.objects.filter(email=email).exists():

            messages.error(
                request,
                "Email Already Exists."
            )

            return redirect('/myapp/user_register/#a')


        user = User()

        user.username = username
        user.password = make_password(password)
        user.first_name = name
        user.email = email

        user.save()

        group=Group.objects.get(name='user')
        user.groups.add(group)



        userdata = User_data()

        userdata.LOGIN = user
        userdata.name = name
        userdata.phone = phone
        userdata.Adress = Adress
        userdata.status = 'Active'

        userdata.save()


        messages.success(
            request,
            f"{name} Account Created Successfully."
        )

        return redirect('/myapp/login_page/#a')


    return render(request, 'user_register.html')

def logout_page(request):
    logout(request)
    messages.success(request, "Logout Success.")

    return redirect('/myapp/login_page/#a')






from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
import random


def forgot_password(request):

    if request.method == 'POST':

        email = request.POST.get('email', '').strip()

        # Check email
        if not email:
            messages.error(
                request,
                "Please enter your email address."
            )
            return redirect('/myapp/forgot_password/#a')

        # Find user
        try:
            user = User.objects.get(email=email)

        except User.DoesNotExist:
            messages.error(
                request,
                "No account found with this email."
            )
            return redirect('/myapp/forgot_password/#a')

        # Generate random 6 digit password
        new_password = str(random.randint(100000, 999999))

        # Send password to email
        try:

            send_mail(
                'SHIELDNET - New Password',

                f'''Hello {user.first_name},

Your SHIELDNET password has been reset.

Your new password is:

{new_password}

Please use this password to login to your SHIELDNET account.

Regards,
SHIELDNET Security Team
''',

                None,
                [email],
                fail_silently=False
            )

        except Exception:

            messages.error(
                request,
                "Unable to send email. Please try again later."
            )

            return redirect('/myapp/forgot_password/#a')

        # Save new password
        user.password = make_password(new_password)
        user.save()

        # Success message
        messages.success(
            request,
            "New password has been sent to your email."
        )

        return redirect('/myapp/login_page/#a')

    return render(
        request,
        'forgot_password.html'
    )


import re
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Q, Count
from django.utils import timezone
from datetime import timedelta
import json




@login_required(login_url='/myapp/login_page/')
def admin_home(request):
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # ---------- Users ----------
    all_users = User_data.objects.select_related('LOGIN').order_by('-created_at')
    total_users = all_users.count()
    blocked_users = all_users.filter(status__iexact='blocked').count()
    active_users = all_users.filter(status__iexact='active').count()

    # ---------- Scans (last 24h) ----------
    scans_24h = Network_Scan_table.objects.filter(timestamp__gte=last_24h).count()

    # ---------- Threats ----------
    phishing_threats = PhishingDetection.objects.filter(
        created_at__gte=last_24h, result__iexact='PHISHING'
    ).count()
    apk_threats = Apk_File_table.objects.filter(
        timestamp__gte=last_24h
    ).filter(
        Q(prediction_result__icontains='CRITICAL MALWARE') |
        Q(prediction_result__icontains='SUSPICIOUS')
    ).count()
    total_threats = phishing_threats + apk_threats

    # ---------- Chart Data ----------
    # 1. User status pie
    chart_user_status = {
        'labels': ['Active', 'Blocked', 'Other'],
        'data': [
            active_users,
            blocked_users,
            max(0, total_users - active_users - blocked_users)
        ]
    }

    # 2. Threat types (24h)
    chart_threats = {
        'labels': ['Phishing', 'APK Threats', 'Clean'],
        'data': [
            phishing_threats,
            apk_threats,
            max(0, scans_24h + phishing_threats + apk_threats - total_threats)
        ]
    }

    # 3. Last 7 days activity (scans + phishing + apk per day)
    days = []
    network_counts = []
    phishing_counts = []
    apk_counts = []

    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        days.append(day.strftime('%d %b'))

        network_counts.append(
            Network_Scan_table.objects.filter(timestamp__date=day).count()
        )
        phishing_counts.append(
            PhishingDetection.objects.filter(created_at__date=day).count()
        )
        apk_counts.append(
            Apk_File_table.objects.filter(timestamp__date=day).count()
        )

    chart_weekly = {
        'labels': days,
        'network': network_counts,
        'phishing': phishing_counts,
        'apk': apk_counts,
    }

    # 4. Phishing vs Legitimate overall
    total_phish = PhishingDetection.objects.filter(result__iexact='PHISHING').count()
    total_legit = PhishingDetection.objects.filter(result__iexact='LEGITIMATE').count()
    chart_phishing = {
        'labels': ['Phishing', 'Legitimate'],
        'data': [total_phish, total_legit]
    }

    # ---------- Latest tables ----------
    latest_scans = Network_Scan_table.objects.select_related('USER').order_by('-timestamp')[:8]
    latest_phish = PhishingDetection.objects.select_related('USER').order_by('-created_at')[:8]
    latest_apks = Apk_File_table.objects.select_related('USER').order_by('-timestamp')[:8]

    # ---------- Activity ----------
    activity = []
    for s in Network_Scan_table.objects.select_related('USER').order_by('-timestamp')[:5]:
        activity.append({
            'time': s.timestamp,
            'event': 'Network scan',
            'user': s.USER.name if s.USER else str(s.USER),
            'status': s.status or 'Clean',
            'status_class': 'warn' if s.status and s.status.lower() == 'suspicious' else 'ok'
        })
    for p in PhishingDetection.objects.select_related('USER').order_by('-created_at')[:5]:
        activity.append({
            'time': p.created_at,
            'event': 'Phishing check',
            'user': p.USER.name if p.USER else str(p.USER),
            'status': p.result or '—',
            'status_class': 'bad' if p.result and p.result.upper() == 'PHISHING' else 'ok'
        })
    for a in Apk_File_table.objects.select_related('USER').order_by('-timestamp')[:5]:
        pred = (a.prediction_result or '').upper()
        if 'CRITICAL MALWARE' in pred:
            status, cls = 'Critical Malware', 'bad'
        elif 'SUSPICIOUS' in pred:
            status, cls = 'Suspicious', 'warn'
        else:
            status, cls = 'Safe', 'ok'
        activity.append({
            'time': a.timestamp,
            'event': 'APK scan',
            'user': a.USER.name if a.USER else str(a.USER),
            'status': status,
            'status_class': cls
        })
    activity = sorted(activity, key=lambda x: x['time'], reverse=True)[:8]

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'blocked_users': blocked_users,
        'scans_24h': scans_24h,
        'total_threats': total_threats,
        'phishing_threats': phishing_threats,
        'apk_threats': apk_threats,
        'all_users': all_users[:20],
        'latest_scans': latest_scans,
        'latest_phish': latest_phish,
        'latest_apks': latest_apks,
        'activity': activity,

        # Chart data (JSON safe)
        'chart_user_status': json.dumps(chart_user_status),
        'chart_threats': json.dumps(chart_threats),
        'chart_weekly': json.dumps(chart_weekly),
        'chart_phishing': json.dumps(chart_phishing),
    }
    return render(request, 'admin/admim home.html', context)

@login_required(login_url='/myapp/login_page/')

def admin_view_users(request):
    a=User_data.objects.all()
    return render(request,'admin/view users.html',{'userdata':a})

@login_required(login_url='/myapp/login_page/')

def admin_view_blocked_users(request):
    a=User_data.objects.filter(status='Blocked')
    return render(request,'admin/view blocked users.html',{'userdata':a})


from django.core.cache import cache
from django.contrib import messages
from django.shortcuts import redirect
from .models import User_data

def admin_unblock_users(request, id):
    User_data.objects.filter(id=id).update(status='Active')
    cache.delete(f"dos_track_user_{id}")
    messages.success(request, "User unblocked successfully.")
    return redirect('/myapp/admin_view_users/#a')



@login_required(login_url='/myapp/login_page/')

def admin_view_complaint_and_reply(request):
    a = Complaint_table.objects.all().order_by('-id')

    if request.method == 'POST':
        complaint_id = request.POST.get('complaint_id') or request.session.get('id')

        if complaint_id:
            aa = Complaint_table.objects.get(id=complaint_id)
            aa.reply = request.POST['reply']
            aa.save()
            messages.success(request, "Reply sent successfully")
        else:
            messages.error(request, "Something went wrong. Please try again.")

        return redirect('/myapp/admin_view_complaint_and_reply/#a')

    return render(request, 'admin/admin_view_complaint_and_reply.html', {'data': a})

@login_required(login_url='/myapp/login_page/')

def admin_view_feedback(request):
    feedbacks = Feedback_table.objects.all().order_by('-id')
    return render(request, 'admin/admin_view_feedback.html', {'feedbacks': feedbacks})
@login_required(login_url='/myapp/login_page/')

def admin_view_network_scan_logs(request):
    logs = Network_Scan_table.objects.all().order_by('-id')
    return render(request, 'admin/admin_network_scan_logs.html', {'logs': logs})

@login_required(login_url='/myapp/login_page/')

def admin_view_phishing_logs(request):
    logs = PhishingDetection.objects.all().order_by('-id')
    return render(request, 'admin/admin_phishing_logs.html', {'logs': logs})

@login_required(login_url='/myapp/login_page/')

def admin_view_apk_scan_logs(request):
    logs = Apk_File_table.objects.all().order_by('-id')
    return render(request, 'admin/admin_apk_scan_logs.html', {'logs': logs})



# user===============================
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Q
import re

from .models import (
    User_data,
    Network_Scan_table,
    Dos_detection_table,
    PhishingDetection,
    Apk_File_table,
)


@login_required(login_url='/myapp/login_page/')
def userhome(request):
    try:
        user_profile = User_data.objects.get(LOGIN=request.user)
    except User_data.DoesNotExist:
        user_profile = None

    # Defaults
    open_ports = "—"
    network_status = "Clean"
    phishing_status = "No Data"
    apk_verdict = "Safe"
    request_rate_status = "Monitoring"
    sandbox_status = "Isolated"
    total_scans = 0
    total_phishing = 0
    total_apks = 0

    if user_profile:
        user_scans = Network_Scan_table.objects.filter(USER=user_profile)
        user_phish = PhishingDetection.objects.filter(USER=user_profile)
        user_apks = Apk_File_table.objects.filter(USER=user_profile)
        user_dos = Dos_detection_table.objects.filter(USER=user_profile)

        total_scans = user_scans.count()
        total_phishing = user_phish.count()
        total_apks = user_apks.count()

        # Latest Network Scan
        latest_scan = user_scans.order_by('-timestamp').first()
        if latest_scan:
            if latest_scan.scanresult:
                match = re.search(r'(\d+)\s*(?:open|ports?)', latest_scan.scanresult, re.I)
                open_ports = match.group(1) if match else "N/A"
            network_status = latest_scan.status or "Clean"

        # Latest Phishing
        latest_phish = user_phish.order_by('-created_at').first()
        if latest_phish and latest_phish.result:
            phishing_status = latest_phish.result.upper()

        # Latest APK
        latest_apk = user_apks.order_by('-timestamp').first()
        if latest_apk and latest_apk.prediction_result:
            pred = latest_apk.prediction_result.upper()
            if "CRITICAL MALWARE" in pred:
                apk_verdict = "Critical Malware"
            elif "SUSPICIOUS" in pred:
                apk_verdict = "Suspicious"

        # DoS / Request Rate
        blocked = user_dos.filter(
            Q(prediction_result__icontains='block') |
            Q(prediction_result__icontains='attack')
        ).count()
        if blocked > 0:
            request_rate_status = "Attack Detected"
        elif user_dos.count() > 5:
            request_rate_status = "Elevated"

    context = {
        'user_profile': user_profile,
        'open_ports': open_ports,
        'network_status': network_status,
        'phishing_status': phishing_status,
        'apk_verdict': apk_verdict,
        'request_rate_status': request_rate_status,
        'sandbox_status': sandbox_status,
        'total_scans': total_scans,
        'total_phishing': total_phishing,
        'total_apks': total_apks,
    }
    return render(request, 'user/userhome.html', context)

@login_required(login_url='/myapp/login_page/')

def user_view_and_sent_complaints(request):
    a=Complaint_table.objects.filter(USER__LOGIN_id=request.user.id)
    if request.method == 'POST':
        subject=request.POST['subject']
        complaint=request.POST['complaint']
        a=Complaint_table()
        a.reply='Pending'
        a.USER=User_data.objects.get(LOGIN_id=request.user.id)
        a.subject=subject
        a.complaint=complaint
        a.save()
        messages.success(request, "Complaint sent successfully")
        return redirect('/myapp/user_view_and_sent_complaints/#a')

    return render(request,'user/user_view_and_sent_complaints.html',{'complaints':a})
@login_required(login_url='/myapp/login_page/')

def user_view_and_send_feedback(request):
    feedbacks = Feedback_table.objects.filter(USER__LOGIN_id=request.user.id).order_by('-id')

    if request.method == 'POST':
        feedback_text = request.POST.get('feedback')
        rating = request.POST.get('rating')

        fb = Feedback_table()
        fb.USER = User_data.objects.get(LOGIN_id=request.user.id)
        fb.feedback = feedback_text
        fb.rating = rating
        fb.save()

        messages.success(request, "Feedback submitted successfully")
        return redirect('/myapp/user_view_and_send_feedback/#a')

    return render(request, 'user/user_feedback.html', {'feedbacks': feedbacks})





@login_required(login_url='/myapp/login_page/')

def user_view_profile(request):
    try:
        profile = User_data.objects.get(LOGIN_id=request.user.id)
    except User_data.DoesNotExist:
        messages.error(request, "Profile not found.")
        return redirect('/myapp/userhome/')

    return render(request, 'user/view_profile.html', {'profile': profile})

@login_required(login_url='/myapp/login_page/')

def user_edit_profile(request):
    try:
        profile = User_data.objects.get(LOGIN_id=request.user.id)
    except User_data.DoesNotExist:
        messages.error(request, "Profile not found.")
        return redirect('/myapp/userhome/')

    if request.method == 'POST':
        name = request.POST.get('name')
        phone = request.POST.get('phone')
        address = request.POST.get('Adress')
        email = request.POST.get('email')

        profile.name = name
        profile.phone = phone
        profile.Adress = address
        profile.save()

        user = profile.LOGIN
        user.first_name = name
        user.email = email
        user.save()

        messages.success(request, "Profile updated successfully.")
        return redirect('/myapp/user_view_profile/#a')

    return render(request, 'user/edit_profile.html', {'profile': profile})





# phishing =======================

# from django.shortcuts import render
# from django.http import JsonResponse
# from .phishing import predict_phishing
#
# def phishing_detection(request):
#     context = {
#         "result": None,
#         "url": "",
#         "phishing_probability": None,
#         "legitimate_probability": None,
#         "error": None,
#     }
#
#     if request.method == "POST":
#         url = request.POST.get("url", "").strip()
#         context["url"] = url
#
#         if not url:
#             context["error"] = "Please enter a URL."
#             return render(request, "user/phishing_detection.html", context)
#
#         if len(url) > 2048:
#             context["error"] = "URL is too long."
#             return render(request, "user/phishing_detection.html", context)
#
#         try:
#             result = predict_phishing(url)
#             context["result"] = result["result"]
#             context["phishing_probability"] = result["phishing_probability"]
#             context["legitimate_probability"] = result["legitimate_probability"]
#         except Exception as e:
#             print("Phishing detection error:", e)
#             context["error"] = "Unable to analyse this URL. Please try again."
#
#     return render(request, "user/phishing_detection.html", context)
#
#
# def phishing_detection_api(request):
#     if request.method != "POST":
#         return JsonResponse({"success": False, "error": "POST request required."}, status=405)
#
#     url = request.POST.get("url", "").strip()
#
#     if not url:
#         return JsonResponse({"success": False, "error": "URL is required."}, status=400)
#
#     try:
#         result = predict_phishing(url)
#         return JsonResponse({
#             "success": True,
#             "url": url,
#             "result": result["result"],
#             "phishing_probability": result["phishing_probability"],
#             "legitimate_probability": result["legitimate_probability"],
#         })
#     except Exception as e:
#         print("API phishing detection error:", e)
#         return JsonResponse({"success": False, "error": "Unable to analyse URL."}, status=500)



from django.shortcuts import render
from django.http import JsonResponse

from .phishing import predict_phishing
from .models import User_data, PhishingDetection


def phishing_detection(request):

    context = {
        "result": None,
        "url": "",
        "phishing_probability": None,
        "legitimate_probability": None,
        "error": None,
    }

    if request.method == "POST":

        url = request.POST.get("url", "").strip()

        context["url"] = url

        # -----------------------------------------
        # URL EMPTY CHECK
        # -----------------------------------------

        if not url:
            context["error"] = "Please enter a URL."

            return render(
                request,
                "user/phishing_detection.html",
                context
            )

        # -----------------------------------------
        # URL LENGTH CHECK
        # -----------------------------------------

        if len(url) > 2048:

            context["error"] = "URL is too long."

            return render(
                request,
                "user/phishing_detection.html",
                context
            )

        # -----------------------------------------
        # ML PREDICTION
        # -----------------------------------------

        try:

            result = predict_phishing(url)

            detection_result = result["result"]

            phishing_probability = result[
                "phishing_probability"
            ]

            legitimate_probability = result[
                "legitimate_probability"
            ]

            # -----------------------------------------
            # SEND RESULT TO HTML
            # -----------------------------------------

            context["result"] = detection_result

            context["phishing_probability"] = (
                phishing_probability
            )

            context["legitimate_probability"] = (
                legitimate_probability
            )

            # -----------------------------------------
            # GET LOGGED-IN USER
            # -----------------------------------------

            try:

                user_data = User_data.objects.get(
                    LOGIN_id=request.user.id
                )

            except User_data.DoesNotExist:

                context["error"] = (
                    "User profile not found."
                )

                return render(
                    request,
                    "user/phishing_detection.html",
                    context
                )

            # -----------------------------------------
            # SAVE PHISHING DETECTION
            # -----------------------------------------

            PhishingDetection.objects.create(

                USER=user_data,

                url=url,

                result=detection_result,

                probability=phishing_probability

            )

            print(
                "Phishing detection saved successfully."
            )

        except Exception as e:

            print(
                "Phishing detection error:",
                e
            )

            context["error"] = (
                "Unable to analyse this URL. "
                "Please try again."
            )

    return render(
        request,
        "user/phishing_detection.html",
        context
    )


# =====================================================
# PHISHING DETECTION API
# =====================================================

def phishing_detection_api(request):

    if request.method != "POST":

        return JsonResponse(
            {
                "success": False,
                "error": "POST request required."
            },
            status=405
        )

    url = request.POST.get(
        "url",
        ""
    ).strip()

    # -----------------------------------------
    # URL CHECK
    # -----------------------------------------

    if not url:

        return JsonResponse(
            {
                "success": False,
                "error": "URL is required."
            },
            status=400
        )

    if len(url) > 2048:

        return JsonResponse(
            {
                "success": False,
                "error": "URL is too long."
            },
            status=400
        )

    # -----------------------------------------
    # ML PREDICTION
    # -----------------------------------------

    try:

        result = predict_phishing(url)

        detection_result = result["result"]

        phishing_probability = result[
            "phishing_probability"
        ]

        legitimate_probability = result[
            "legitimate_probability"
        ]

        # -----------------------------------------
        # GET LOGGED-IN USER
        # -----------------------------------------

        try:

            user_data = User_data.objects.get(
                LOGIN_id=request.user.id
            )

        except User_data.DoesNotExist:

            return JsonResponse(
                {
                    "success": False,
                    "error": "User profile not found."
                },
                status=404
            )

        # -----------------------------------------
        # SAVE DETECTION
        # -----------------------------------------

        PhishingDetection.objects.create(

            USER=user_data,

            url=url,

            result=detection_result,

            probability=phishing_probability

        )

        # -----------------------------------------
        # RETURN API RESPONSE
        # -----------------------------------------

        return JsonResponse(
            {
                "success": True,

                "url": url,

                "result": detection_result,

                "phishing_probability":
                    phishing_probability,

                "legitimate_probability":
                    legitimate_probability,
            }
        )

    except Exception as e:

        print(
            "API phishing detection error:",
            e
        )

        return JsonResponse(
            {
                "success": False,
                "error": "Unable to analyse URL."
            },
            status=500
        )



# apk malware checking using Sandbox


import base64
import requests
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Apk_File_table, Sandbox_table, User_data

def upload_and_sandbox_apk(request):
    current_user = User_data.objects.get(LOGIN_id=request.user.id)

    if request.method == 'POST' and request.FILES.get('apk_file'):
        uploaded_file = request.FILES['apk_file']

        apk_record = Apk_File_table.objects.create(
            USER=current_user,
            apk_file=uploaded_file,
            confidence_score="0.0%",
            prediction_result="DISPATCHED_TO_SANDBOX"
        )

        uploaded_file.seek(0)
        file_bytes = uploaded_file.read()
        encoded_content = base64.b64encode(file_bytes).decode('utf-8')

        sandbox_endpoint = f"{settings.SANDBOX_ENGINE_URL}/analyze"

        try:
            response = requests.post(
                sandbox_endpoint,
                json={
                    'filename': uploaded_file.name,
                    'content_base64': encoded_content
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()

                threat_score = result.get('threat_score', 0)
                verdict = result.get('verdict', 'SUSPICIOUS')
                signatures = result.get('detected_signatures', 'None')
                execution_logs = result.get('execution_logs', '')

                apk_record.confidence_score = f"{threat_score}%"
                apk_record.prediction_result = f"{verdict} | Sigs: {signatures}"
                apk_record.save()

                summary = (
                    f"Port {settings.SANDBOX_ENGINE_PORT} [ISOLATED] | "
                    f"Threat: {threat_score}% | Entropy: {result.get('entropy', 0.0)} | "
                    f"Verdict: {verdict}"
                )

                Sandbox_table.objects.create(
                    APK=apk_record,
                    sandbox_status="COMPLETED",
                    behaviour_summary=summary[:255],
                    executed_on_server="FALSE (Executed inside Sandbox Node Port 5000)"
                )

                messages.success(request, f"Sandbox Analysis Completed: {verdict} ({threat_score}%)")
                return redirect('/myapp/view_apk_reports/#a')

            else:
                apk_record.prediction_result = "SANDBOX_ANALYSIS_FAILED"
                apk_record.save()
                messages.error(request, f"Sandbox daemon returned error code: {response.status_code}")

        except requests.exceptions.ConnectionError:
            apk_record.prediction_result = "SANDBOX_DAEMON_OFFLINE"
            apk_record.save()
            messages.error(
                request,
                f"Sandbox microservice is not running on port {settings.SANDBOX_ENGINE_PORT}. Please start run_sandbox.py"
            )

        return redirect('/myapp/view_apk_reports/#a')

    return render(request, 'user/user_upload_apk.html')

from django.shortcuts import render
from .models import Apk_File_table, User_data

def view_apk_reports(request):
    current_user = User_data.objects.get(LOGIN_id=request.user.id)
    reports = Apk_File_table.objects.filter(USER=current_user).prefetch_related('sandbox_table_set').order_by('-id')
    return render(request, 'user/user_apk_reports.html', {'reports': reports})





from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .models import User_data, Network_Scan_table
from .nmap_scan import run_nmap_scan


@login_required(login_url='/myapp/login_page/')
def network_scan(request):

    if request.method == 'POST':


        target_host = request.POST.get(
            'target_host',
            ''
        ).strip()

        if not target_host:

            return render(
                request,
                'user/network_scan.html',
                {
                    'error': 'Please enter an IP address or host.'
                }
            )

        try:

            user_data = User_data.objects.get(
                LOGIN_id=request.user.id
            )


            scanresult, status = run_nmap_scan(
                target_host
            )


            Network_Scan_table.objects.create(
                USER=user_data,
                target_host=target_host,
                scanresult=scanresult,
                status=status
            )


            return render(
                request,
                'user/network_scan.html',
                {
                    'result': scanresult,
                    'status': status,
                    'target_host': target_host
                }
            )

        except User_data.DoesNotExist:

            return render(
                request,
                'user/network_scan.html',
                {
                    'error': 'User profile not found.'
                }
            )

        except Exception as e:

            return render(
                request,
                'user/network_scan.html',
                {
                    'error': str(e),
                    'target_host': target_host
                }
            )

    # -----------------------------------------
    # GET REQUEST
    # -----------------------------------------
    return render(
        request,
        'user/network_scan.html'
    )




from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from .models import User_data, Chat_table


@login_required
def all_users(request):

    users = User_data.objects.exclude(
        LOGIN=request.user
    )

    return render(
        request,
        'user/all_users.html',
        {
            'users': users
        }
    )


def user_chat_to_user(request, id):
    request.session["userid"] = id
    cid = str(request.session["userid"])
    request.session["new"] = cid
    qry = User_data.objects.get(LOGIN=cid)
    print(qry.LOGIN.id,'login----------')

    return render(request, "user/Chat.html", { 'name': qry.name, 'toid': cid})


def chat_view(request):
    fromid = request.user.id
    toid = request.session["userid"]
    qry = User_data.objects.get(LOGIN_id=request.session["userid"])
    from django.db.models import Q

    res = Chat_table.objects.filter(Q(FROM_id=fromid, TO_id=toid) | Q(FROM_id=toid, TO_id=fromid)).order_by('id')
    l = []
    print(qry.name,'userssssssssss')

    for i in res:
        l.append({"id": i.id, "message": i.chat, "to": i.TO_id, "date": i.timestamp, "from": i.FROM_id})

    return JsonResponse({ "data": l, 'name': qry.name, 'toid': request.session["userid"]})


def chat_send(request, msg):
    lid = request.user.id
    toid = request.session["userid"]
    message = msg

    import datetime
    d = datetime.datetime.now().date()
    chatobt = Chat_table()
    chatobt.chat = message
    chatobt.TO_id = toid
    chatobt.FROM_id = lid
    chatobt.timestamp = d
    chatobt.save()

    return JsonResponse({"status": "ok"})