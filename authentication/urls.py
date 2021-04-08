from django.urls import path
from . import views
from rest_framework.authtoken.views import obtain_auth_token
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView


from .forms import UserLoginForm
# PwdResetConfirmForm, PwdResetForm, 


app_name="authentication"


urlpatterns = [
    path('getcsrf/default/',views.get_csrf),
    path('signinsave/', views.signinsave,name="signinsave"),
    path('signupsave/', views.signupSave,name="signupsave"),

    path('login-popup/', auth_views.LoginView.as_view(template_name="login.html", form_class=UserLoginForm, extra_context={'action':'Login','title':'Login | Dudemy'}),name="login"),
    path('signup-popup/', views.signupView.as_view(),name="signup"),

     path("activate/<slug:uidb64>/<slug:token>)/", views.account_activate, name="activate"),

    # Rest Paths
    path('api/api-token-auth/', obtain_auth_token,name="apilogin"),
]