from django.contrib.auth.decorators import login_required
from myapp.models import *
from django.contrib.auth.models import User, Group
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from .middleware import render_dos_blocked_page

def public_home(request):
    return render(request,'public page.html')

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


@login_required(login_url='/myapp/login_page/')

def admin_home(request):
    return render(request,'admin/admim home.html')



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
    User_data.objects.filter(id=id).update(status='active')
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
@login_required(login_url='/myapp/login_page/')

def userhome(request):
    return render(request,'user/userhome.html')

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
