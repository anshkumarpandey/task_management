from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import Task

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        # Get the default JWT token
        token = super().get_token(user)

        # Add custom claims (for example, adding the username to the token)
        token['username'] = user.username
        return token
class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'completed', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']  # These fields will not be editable
#superuser username-->anshkumarpandey
#superuser password-->storyvord