from django import forms
from django.contrib.auth.forms import (AuthenticationForm, PasswordResetForm,
                                       SetPasswordForm)
from django.contrib.auth.models import User

class UserLoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control mb-3', 'placeholder': 'Username', 'id': 'login-username'}))
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={
            'class': 'form-control',
            'placeholder': 'Password',
            'id': 'login-pwd',
        }
    ))

class RegistrationForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control mb-3', 'placeholder': 'Username', 'id': 'signup-username'}), min_length=4, max_length=50, help_text='Required')

    # username = forms.CharField(
    #     label='Enter Username', min_length=4, max_length=50, help_text='Required')

    email = forms.EmailField(widget=forms.TextInput(
        attrs={'class': 'form-control mb-3', 'placeholder': 'Email', 'id': 'signup-username'}),max_length=100, help_text='Required', error_messages={
        'required': 'Sorry, you will need an email'})

    password = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={'class': 'form-control mb-3', 'placeholder': 'password', 'id': 'signup-password'}))
    password2 = forms.CharField(
        label='Repeat password', widget=forms.PasswordInput(attrs={'class': 'form-control mb-3', 'placeholder': 'Confirm Password', 'id': 'signup-password2'}))

    class Meta:
        model = User
        fields = ('username', 'email',)

    def clean_username(self):
        username = self.cleaned_data['username'].lower()
        r = User.objects.filter(username=username)
        if r.count():
            raise forms.ValidationError("Username already exists")
        return username

    def clean_password2(self):
        cd = self.cleaned_data
        if cd['password'] != cd['password2']:
            raise forms.ValidationError('Passwords do not match.')
        return cd['password2']