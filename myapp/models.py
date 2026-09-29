from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class User_data(models.Model):
    LOGIN = models.ForeignKey(User,on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)
    status = models.CharField(max_length=20)
    Adress = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)


class Network_Scan_table(models.Model):
    USER = models.ForeignKey(User_data,on_delete=models.CASCADE)
    target_host = models.CharField(max_length=255)
    scanresult = models.TextField()
    status = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)


class Dos_detection_table(models.Model):
    USER = models.ForeignKey(User_data,on_delete=models.CASCADE)
    url = models.CharField(max_length=255)
    confidence_score = models.CharField(max_length=255)
    prediction_result = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


class PhishingDetection(models.Model):
    USER = models.ForeignKey(User_data,on_delete=models.CASCADE)

    url = models.URLField(max_length=2048)

    result = models.CharField(max_length=20)

    probability = models.FloatField()

    created_at = models.DateTimeField(auto_now_add=True)


class Apk_File_table(models.Model):
    USER = models.ForeignKey(User_data,on_delete=models.CASCADE)
    apk_file = models.FileField()
    confidence_score = models.CharField(max_length=255)
    prediction_result = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


class Sandbox_table(models.Model):
    APK = models.ForeignKey(Apk_File_table,on_delete=models.CASCADE)
    sandbox_status = models.CharField(max_length=255)
    behaviour_summary = models.TextField()
    executed_on_server = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)


class Chat_table(models.Model):
    FROM = models.ForeignKey(User,on_delete=models.CASCADE,related_name='from_id')
    TO = models.ForeignKey(User,on_delete=models.CASCADE,related_name='to_id')
    chat = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)



class Complaint_table(models.Model):
    USER = models.ForeignKey(User_data,on_delete=models.CASCADE)
    subject = models.CharField(max_length=255)
    complaint = models.CharField(max_length=255)
    reply = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)


class Feedback_table(models.Model):
    USER = models.ForeignKey(User_data,on_delete=models.CASCADE)
    feedback = models.CharField(max_length=255)
    rating = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)




