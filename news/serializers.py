from rest_framework import serializers
from django.contrib.auth.models import User
from .models import  Content, Discussion, Photo, Favorite ,User ,Category
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = User
        fields =  ['email','user_name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    def save(self):
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError(
                {'error': 'passwords did not match'})

        user = User(email=self.validated_data['email'],
                    user_name=self.validated_data['user_name'],is_active=True)
        user.set_password(self.validated_data['password'])
        user.save()
        return user
  # # We are writing this becoz we need confirm password field in our Registratin Request
  # password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
  # class Meta:
  #   model = User
  #   fields=['email', 'user_name', 'password', 'password2',]
  #   extra_kwargs={
  #     'password':{'write_only':True}
  #   }

  # # Validating Password and Confirm Password while Registration
  # def validate(self, attrs):
  #   password = attrs.get('password')
  #   password2 = attrs.get('password2')
  #   if password != password2:
  #     raise serializers.ValidationError("Password and Confirm Password doesn't match")
  #   return attrs

  # def create(self, validate_data):
  #   return User.objects.create_user(**validate_data)

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id', 'email', 'user_name']

class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']

  def validate(self, attrs):
    email = attrs.get('email')
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://localhost:8000/api/user/reset-password/'+uid+'/'+token+'/'
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')
   




                    
class VerifyOTPSerializer(serializers.Serializer):

    email = serializers.EmailField()
    otp = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields ="__all__"

# # Register Serializer
# class RegisterSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ('id', 'username', 'email', 'password')
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self, validated_data):
#         user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])
#         return user



class CategorySerializer(serializers.ModelSerializer):
     class Meta:
          model = Category
        #   read_only_fields =("Categoty")
          fields='__all__'
      

class ChangePasswordSerializer(serializers.Serializer):
    model = User

    old_pass = serializers.CharField(required=True)

    new_pass = serializers.CharField(required=True)


# class LearningSpaceSerializer(serializers.ModelSerializer):
#     members = UserSerializer(many=True, read_only=True)
#     ls_owner=UserSerializer(read_only=True)
    
    
#     class Meta:
#         model = LearningSpace
#         fields = ["id", "name", "members", "tag", "ls_owner", "description","created_on"]

# class LearningSpacePostSerializer(serializers.ModelSerializer):
#     members = UserSerializer(many=True, read_only=True)
    
    
    
#     class Meta:
#         model = LearningSpace
#         fields = ["id", "name", "members", "tag", "ls_owner", "description","created_on"]

class PhotoSerializer(serializers.ModelSerializer):

    class Meta:
        model = Photo
        fields = ['content','image']

class ContentSerializer(serializers.ModelSerializer):
    photos = serializers.SerializerMethodField()

    def get_photos(self, obj):
        photos = Photo.objects.filter(content=obj)
        return PhotoSerializer(photos, many=True, read_only=False).data
    class Meta:
        model = Content
        fields = ["photos", "id","name","title", "categories", "body","created_on", "owner","post", "upVoteCount"]

    body = serializers.CharField(default="")
    # url = serializers.CharField(max_length=30, default="")
    upVoteCount = serializers.IntegerField(default=0)

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.categories = validated_data.get('categories', instance.categories)
        instance.body = validated_data.get('body', instance.body)
        # instance.url = validated_data.get('url', instance.url)
        instance.upVoteCount = validated_data.get('upVoteCount', instance.url)

        instance.save()
        return instance


    # def validate(self, data):
    #     # TODO: fill each condition with the correct validations (whether it is really a video, image, etc.)
    #     # if data['type'] == "text":
    #     #     if data.get("text", "") == "":
    #     #         raise serializers.ValidationError("Type doesn't match the content")
    #     elif data['type'] == "video":
    #         if data.get("url", "") == "":
    #             raise serializers.ValidationError("Type doesn't match the content")
    #     elif data['type'] == "image":
    #         if data.get("url", "") == "":
    #             raise serializers.ValidationError("Type doesn't match the content")
   
    #     return data


class DiscussionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Discussion
        #fields = '__all__'
        fields = ["id", "content", "owner", "body", "created_on"]
    owner =  UserSerializer()


class DiscussionPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Discussion
        #fields = '__all__'
        fields = ["id", "content", "owner", "body", "created_on"]

# class NoteSerializer(serializers.ModelSerializer):
    # class Meta:
    #     model = Note
    #     #fields = '__all__'
    #     fields = ["id", "content", "owner", "body", "created_on"]
    # owner =  UserSerializer()


# class NotePostSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Note
#         #fields = '__all__'
#         fields = ["id", "content", "owner", "body", "created_on"]



class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = '_all_'
        fields = ["id","email","user_name", "about_me", "image","rating"]  
    image = serializers.FileField()
    # learningspaces = LearningSpaceSerializer(many=True, read_only=True)


    
class ResetSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)

 


class FavoriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Favorite
        fields = ["id", "user", "learningSpace"]
    # learningSpace = LearningSpaceSerializer()


class FavoritePostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Favorite
        fields = ["id", "user", "learningSpace"]

    

    