
from django.urls import path, include

from myapp import views

urlpatterns = [

    path('public_home/',views.public_home),
    path('login_page/',views.login_page),
    path('logout_page/',views.logout_page),
    path('user_register/',views.user_register),
    path('forgot_password/',views.forgot_password),

    path('admin_home/',views.admin_home),
    path('admin_view_users/',views.admin_view_users),
    path('admin_view_blocked_users/',views.admin_view_blocked_users),
    path('admin_unblock_users/<id>/',views.admin_unblock_users),
    path('admin_view_complaint_and_reply/',views.admin_view_complaint_and_reply),
    path('admin_view_feedback/',views.admin_view_feedback),

    path('admin_view_network_scan_logs/',views.admin_view_network_scan_logs),
    path('admin_view_phishing_logs/',views.admin_view_phishing_logs),
    path('admin_view_apk_scan_logs/',views.admin_view_apk_scan_logs),



    path('userhome/',views.userhome),
    path('user_view_profile/',views.user_view_profile),
    path('user_edit_profile/',views.user_edit_profile),
    path('user_view_and_sent_complaints/',views.user_view_and_sent_complaints),
    path('user_view_and_send_feedback/',views.user_view_and_send_feedback),

    path('phishing-check/', views.phishing_detection, name='phishing_detection'),
    path('api/phishing-check/', views.phishing_detection_api, name='phishing_detection_api'),


    path('apk-sandbox-upload/', views.upload_and_sandbox_apk, name='upload_and_sandbox_apk'),
    path('view_apk_reports/', views.view_apk_reports, name='view_apk_reports'),
    path('network_scan/', views.network_scan, name='network_scan'),



    path( 'all-users/',views.all_users,name='all_users'),

    path( 'chat_view/',views.chat_view,name='chat_view'),
    path( 'user_chat_to_user/<id>/',views.user_chat_to_user,name='user_chat_to_user'),
    path( 'chat_send/<msg>',views.chat_send,name='chat_send'),




]
