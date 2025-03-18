from django.contrib import admin
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path, include
from app1.views import (
    CustomTokenObtainPairView,
    SignupView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    LoginView,
    TaskListCreateView,
    TaskDetailView,
    TaskListView,
    ProtectedView,
    TestAuthView,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset-password/<int:uid>/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('', LoginView.as_view(), name='login'),
    path('protected/',ProtectedView.as_view(), name='protected_view'),
    path('api/tasks/', TaskListCreateView.as_view(), name='task_list_create'),
    path('api/tasks/<int:id>/', TaskDetailView.as_view(), name='task_detail'),
    path('task-list/', TaskListView.as_view(), name='task_list_view'),
     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/test-auth/', TestAuthView.as_view(), name='test_auth'),

]