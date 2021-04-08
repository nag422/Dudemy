from django.shortcuts import render,redirect
from django.http import JsonResponse,HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect,csrf_exempt
from django.middleware.csrf import get_token
import json
from django.views.generic.base import TemplateView,RedirectView
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
# from django.views.generic.edit import FormView
from .tokens import account_activation_token
from .forms import RegistrationForm

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

@ensure_csrf_cookie
def get_csrf(request):
    response = JsonResponse({"Info": "Success - Set CSRF cookie"})
    response["X-CSRFToken"] = get_token(request)
    return response


# @api_view(['POST'])
# @permission_classes([IsAuthenticated])

def signinsave(request):
   
    return Response({'success':'success'})

class loginView(TemplateView):
    template_name = "login.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action'] = 'Login'
        context['title'] = 'Login | Dudemy'
        return context

class signupView(TemplateView):
    template_name = "signup.html"
    
    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action'] = 'Signup'
        context['title'] = 'Signup | Dudemy'
        context['form'] = RegistrationForm()
        return context

def signupSave(request):
    if request.user.is_authenticated:
        return redirect('authentication:login')
    if request.method == "POST":
        try:
            registerForm = RegistrationForm(request.POST)
            print(request.POST)
            if registerForm.is_valid():
                user = registerForm.save(commit=False)
                user.email = registerForm.cleaned_data["email"]
                user.set_password(registerForm.cleaned_data["password"])
                user.is_active = False
                user.save()

                current_site = get_current_site(request)

                subject = "Activate your Account"
                message = render_to_string(
                    "email/account_activation_email.html",
                    {
                        "user": user,
                        "domain": current_site.domain,
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "token": account_activation_token.make_token(user),
                    },
                )
                user.email_user(subject=subject, message=message)
                return redirect('authentication:login')
        except Exception as e:
            print('error',e)
            pass
        
        return redirect('authentication:signup')

def account_activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, user.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return redirect("authentication:login")
    else:
        return redirect('authentication:signup')


