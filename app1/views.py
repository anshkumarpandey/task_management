from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status , serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Task
from .serializers import TaskSerializer, CustomTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

# Protected View for Authenticated Users
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated
    authentication_classes = [JWTAuthentication]  # Use JWTAuthentication

    def get(self, request):
        return Response({"message": "You have access to this protected view!"})
    
    # Custom serializer to extend TokenObtainPairSerializer
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    # You can add additional fields to the token payload here
    username = serializers.CharField()

    def validate(self, attrs):
        data = super().validate(attrs)
        user = User.objects.get(username=attrs['username'])
        
        # You can also include extra fields in the token response if needed
        data['username'] = user.username  # Example: add username to the response
        data['email'] = user.email        # Example: add email to the response
        
        return data


# ----------------------------- Authentication Views -----------------------------

# Custom Token Obtain Pair View
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
class TestAuthView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})

# Signup View
class SignupView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return render(request, 'signup.html')

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if User.objects.filter(username=username).exists():
            return render(request, 'signup.html', {"error": "Username already exists."})
        if User.objects.filter(email=email).exists():
            return render(request, 'signup.html', {"error": "Email already exists."})

        user = User.objects.create(username=username, email=email, password=make_password(password))
        user.save()
        return redirect('login')  # Redirect to login page after successful signup]


# Login View
class LoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            response = redirect('task_list_create')
            response.set_cookie('refresh', str(refresh), httponly=True, samesite='Lax')
            response.set_cookie('access', str(refresh.access_token), httponly=True, samesite='Lax')
            return response
        return render(request, 'login.html', {"error": "Invalid username or password."})

# Password Reset Request View
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return render(request, 'forgot_password.html')

    def post(self, request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = f"{request.build_absolute_uri('/')[:-1]}/reset-password/{user.pk}/{token}"
            send_mail(
                'Password Reset Request',
                f"Click the link to reset your password: {reset_url}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            return render(request, 'forgot_password.html', {"message": "Password reset email sent."})
        return render(request, 'forgot_password.html', {"error": "User with this email does not exist."})

# Password Reset Confirm View
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uid, token):
        return render(request, 'reset_password.html', {'uid': uid, 'token': token})

    def post(self, request, uid, token):
        password = request.POST.get('password')
        user = User.objects.get(pk=uid)
        if PasswordResetTokenGenerator().check_token(user, token):
            user.password = make_password(password)
            user.save()
            return render(request, 'reset_password.html', {"message": "Password has been reset successfully!"})
        return render(request, 'reset_password.html', {"error": "Invalid or expired token."})

# ----------------------------- Task Management Views -----------------------------

# Task List and Create View
class TaskListCreateView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access
    authentication_classes = [JWTAuthentication]  # Use JWT for authentication

    def get(self, request):
        print(request.headers.get('Authorization'))  # Check if the header is sent correctly
        tasks = Task.objects.filter(user=request.user)  # Only retrieve tasks for the logged-in user
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)  # Automatically associate task with the logged-in user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Task Detail View
class TaskDetailView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, id):
        try:
            task = Task.objects.get(id=id, user=request.user)
            serializer = TaskSerializer(task)
            return Response(serializer.data)
        except Task.DoesNotExist:
            return Response({"error": "Task not found or you do not have access."}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, id):
        try:
            task = Task.objects.get(id=id, user=request.user)
            serializer = TaskSerializer(task, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Task.DoesNotExist:
            return Response({"error": "Task not found or you do not have access."}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, id):
        try:
            task = Task.objects.get(id=id, user=request.user)
            task.delete()
            return Response({"message": "Task deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)
        except Task.DoesNotExist:
            return Response({"error": "Task not found or you do not have access."}, status=status.HTTP_404_NOT_FOUND)

# Task List View for HTML Rendering
class TaskListView(LoginRequiredMixin, View):
    login_url = '/login/'

    def get(self, request):
        tasks = Task.objects.filter(user=request.user)
        return render(request, 'task_list.html', {'tasks': tasks})
