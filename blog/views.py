from django.shortcuts import render, HttpResponseRedirect,redirect
from .forms import SignupForm, LoginForm, PostForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Post
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from django.urls import reverse

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
                    return HttpResponseRedirect('/dashboard/')
        else:
            form = LoginForm()
        return render(request, 'blog/login.html', {'form': form})
    else:
        return HttpResponseRedirect('/dashboard/')  


# logout
def user_logout(request):
    logout(request)
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