import jwt
import datetime
from django.conf import settings
from django.shortcuts import render, HttpResponseRedirect,redirect, HttpResponse
from .forms import SignupForm, LoginForm, PostForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Post
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from datetime import datetime, timedelta


# Create your views here.
# home
def home(request):
    posts = Post.objects.all()
    return render(request, 'blog/home.html', {'posts':posts})

# about
def about(request):
    return render(request, 'blog/about.html')

# contact
def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        address = request.POST.get('add', '')
        message = request.POST.get('msg', '')

        subject = f'Contact Form Submission from {name}'
        message_body = f'Name: {name}\nEmail: {email}\nAddress: {address}\n\nMessage:\n{message}'
        from_email = 'divyang.kansara@technostacks.com'  
        to_email = ['divyangtest@yopmail.com', 'divyangkansara21@gmail.com']  

        send_mail(subject, message_body, from_email, to_email, fail_silently=False)

    return render(request, 'blog/contact.html')



# signup
def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST) 
        if form.is_valid():
            user = form.save()
            group = Group.objects.get(name='Author')
            user.groups.add(group)

            # Log in the user after successful signup
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = authenticate(request, username=username, password=password)
            login(request, user)

            messages.success(request, 'Congratulations! You have become an Author')
            return redirect('dashboard')  # Redirect to your dashboard URL

    else:        
        # Check if the user is already authenticated
        if request.user.is_authenticated:
            return redirect('dashboard')  # Redirect to your dashboard URL
        form = SignupForm()

    return render(request, 'blog/signup.html', {'form': form})


# login
def generate_tokens(user):
    # Generate access token
    access_payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRATION_SECONDS)
    }
    access_token = jwt.encode(access_payload, settings.SECRET_KEY)

    # Generate refresh token
    refresh_payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=settings.REFRESH_TOKEN_EXPIRATION_SECONDS)
    }
    refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY)

    return access_token, refresh_token

def user_login(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = LoginForm(request=request, data=request.POST)
            if form.is_valid():
                uname = form.cleaned_data['username']
                upass = form.cleaned_data['password']
                user = authenticate(username=uname, password=upass)
                if user is not None:
                    login(request, user)
                    messages.success(request, 'Logged in successfully!!')

                    access_token, refresh_token = generate_tokens(user)

                    request.session['jwt_access_token'] = access_token
                    request.session['jwt_refresh_token'] = refresh_token


                    print("Access Token:", access_token)
                    print("Refresh Token:", refresh_token)

                    return HttpResponseRedirect('/dashboard/')
        else:
            form = LoginForm() 
        return render(request, 'blog/login.html', {'form': form})
    else:
        return HttpResponseRedirect('/dashboard/')

# dashboard
def dashboard(request):
    if request.user.is_authenticated:
        posts = Post.objects.all()
        user = request.user
        full_name = user.get_full_name()
        gps = user.groups.all()
        return render(request, 'blog/dashboard.html', {'posts': posts,
               'full_name':full_name, 'groups':gps})
    else:
        return HttpResponseRedirect('/login/')

def check_token_details(request):
    if request.user.is_authenticated:
        access_token = request.session.get('jwt_access_token')
        refresh_token = request.session.get('jwt_refresh_token')

        if access_token:
            try:
                decoded_access_token = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = decoded_access_token.get('user_id')
                username = decoded_access_token.get('username')
                exp_time = decoded_access_token.get('exp')

                print("JWT Token Details:")
                print("User ID:", user_id)
                print("Username:", username)
                print("Access Token:", access_token)

                if exp_time:
                    exp_datetime = datetime.utcfromtimestamp(exp_time)  # Convert exp_time to datetime
                    if datetime.utcnow() > exp_datetime + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRATION_SECONDS):
                        print("Access Token expired. Refresh Token:", refresh_token)


            except jwt.ExpiredSignatureError:
                # Access token signature expired
                print("Access Token signature expired. Refresh Token:", refresh_token)
        else:
            print("Access Token not found")

        return HttpResponseRedirect('/dashboard/')
    else:
        return HttpResponseRedirect('/login/')

# logout
def user_logout(request):
    print("Token exists before deletion:", request.session['jwt_access_token'])
    logout(request)
    print("Token exists after deletion:")
    if 'jwt_access_token' in request.session:
        print("Token exists before deletion:", request.session['jwt_access_token'])
        del request.session['jwt_token']
        print("Token deleted...")
    else:
        print("Token not found in session.") 
    return HttpResponseRedirect('/')


# Add New Post
def add_post(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = PostForm(request.POST)
            if form.is_valid():
                title = form.cleaned_data['title']
                desc = form.cleaned_data['desc']
                post = Post(title=title, desc=desc)
                post.save()
                form = PostForm()   
        else:
            form = PostForm()
        return render(request, 'blog/addpost.html', {'form' : form})
    else:
        return HttpResponseRedirect('/login/')
    

# Update Post
def update_post(request, id):
    if request.user.is_authenticated:
        if request.method == 'POST':
            pi = Post.objects.get(pk=id)
            form = PostForm(request.POST, instance=pi)
            if form.is_valid():
                form.save()
        else:
            pi = Post.objects.get(pk=id)
            form = PostForm(instance=pi)
        return render(request, 'blog/updatepost.html', {'form':form})
    else:
        return HttpResponseRedirect('/login/')
    
# delete Post
def delete_post(request, id):
    if request.user.is_authenticated:
        if request.method == 'POST':
            pi = Post.objects.get(pk=id)
            pi.delete()
        return HttpResponseRedirect('/dashboard/')
    else:
        return HttpResponseRedirect('/login/')