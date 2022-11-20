from base64 import urlsafe_b64decode
from django.http import HttpResponse
from django.core.mail import EmailMessage
from gfg import settings
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token


def home(request):
    return render(request,"authentication/index.html")

def signup(request):

        if request.method =="POST":
            username = request.POST['username']
            firstname = request.POST['firstname']
            lastname= request.POST['lastname']
            email  = request.POST['email']
            password = request.POST['password']
            confirm_password = request.POST['confirm password']

            if User.objects.filter(username=username):
                messages.error(request, "User already exists. please try another username")

            if User.objects.filter(email=email):
                messages.error(request, "Email already registered")

            if password != confirm_password:
                messages.error(request, "Passwords do not match")


        
        
        
            myuser = User.objects.create_user(username, email,password)
            myuser.first_name = firstname
            myuser.last_name= lastname
            myuser.is_active = False
            myuser.save()

            messages.success(request, 'Your Account has been successfully created. We have sent you a confirmatio n email, please confirm your email')

            #welcome email message

            subject = "Welcome to Maybee's tech services"
            message = "Hello" + myuser.first_name + " !! \n" + "welcome to Maybee!! \n Thank you for visiting our website.\n We have also sent you a confirmation email, please confirm your email address in order to activate your account"
            from_email = settings.EMAIL_HOST_USER
            to_list = [myuser.email]
            send_mail(subject, message, from_email, to_list, fail_silently=True)

            # Email address confimation message
            current_site = get_current_site(request)
            email_subject = "confirm your email @ emailtesting437"
            message2 = render_to_string("email_confirmation.html",{
                "name": myuser.first_name,
                "domain": current_site.domain,
                "uid": urlsafe_base64_encode(force_bytes(myuser.pk)),
                "token":generate_token.make_token(myuser),
            })
            email = EmailMessage(
                email_subject,
                message2,
                settings.EMAIL_HOST_USER,
                [myuser.email],
            )
            email.fail_silently = True
            email.send()


            return redirect('signin')

        return render(request, "authentication/signup.html")


def signin(request):

    if request.method == "POST":
        username = request.POST['username']
        password = request.POST ['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user) 
            firstname = user.first_name
            return render(request, 'authentication/index.html', {'firstname': firstname})


        else:
            messages.error(request, 'bad credentials' )
            return redirect('home')

    return render(request, "authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request, 'logged out successfully')
    return redirect("home")

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_b64decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist ):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
      myuser.is_active = True  
      myuser.save()
      login(request, myuser)
      return redirect("home")
    else:
        return render(request, "activation_failed.html")



