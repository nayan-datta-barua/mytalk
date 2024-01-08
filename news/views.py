from rest_framework import generics, permissions, status, generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated   
from django.contrib.auth import login
from django.contrib.auth.models import User
# from knox.models import AuthToken
from rest_framework.views import APIView
# from knox.views import LoginView as KnoxLoginView
from rest_framework.authtoken.serializers import AuthTokenSerializer
# from .models import Content, LearningSpace, Discussion, User,Photo, Category
from .models import *
from .serializers import *
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from .helpers import send_forget_password_mail,get_random_string
from .utils import *
from django.shortcuts import render
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
import jwt
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .renderers import UserRenderer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self,request,format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token,'msg':'Registration Success'},status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response(token)
    #   return Response({'token':token,'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
    

class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)
  
class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

  
class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)

class LogoutBlacklistTokenUpdateView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = ()

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            
            return Response(status=status.HTTP_400_BAD_REQUEST)
        



class VerifyOTPAPIView(generics.GenericAPIView):
    def post(self, request, *args, **kwargs):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data['email']
            otp = serializer.data['otp']
            user_obj = User.objects.get(email=email)
            
            if user_obj.otp == otp:
                user_obj.is_staff = True
                user_obj.save()
                return Response("verified")
            return Response(serializer.data,status.HTTP_400_BAD_REQUEST)


class LogoutBlacklistTokenUpdateView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = ()

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            
            return Response(status=status.HTTP_400_BAD_REQUEST)
        


class ChangePassword(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        obj = self.request.user
        return obj

    def update(self, req):
        self.object = self.get_object()
        serialization = self.get_serializer(data=req.data)

        if serialization.is_valid():
            
            #controll the old password
            if self.object.check_password(serialization.data.get("old_pass")):

                return Response({"old_pass": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            
            #assign the password
            self.object.set_password(serialization.data.get("new_pass"))

            self.object.save()
            resp = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully'
            }
            

            return Response(resp)
        else:
            return Response(serialization.errors, status=status.HTTP_400_BAD_REQUEST)
        



class profileApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileSerializer

    def post(self, request, *args, **kwargs):
        
        data = request.data.copy()
        

        data['user'] = request.user.id
        print(data)
        serializer = self.serializer_class(data=data)
        

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, *args, **kwargs):
        data=request.user.id
        print(data)
        print('nayan')
        try:
            user_id = request.GET.get('id', request.user.id)
            print(user_id)
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = User.objects.get(id=user_id)
            profile = self.serializer_class(profile).data
            print(profile)

            # learningspaces=LearningSpace.objects.filter(members__id=data)
            # list=[]
            # for i in learningspaces:
            #     list.append(i.id)

            # profile["learningspaces"] = list
            # print(profile)
            # print("nayan11")   



            # serializer = self.serializer_class1(profile)
            # profile, status=status.HTTP_200_OK
            # {"error":False,"profile":profile}
            return Response(profile, status=status.HTTP_200_OK)
            # return Response(serializer.data, )
        except profile.DoesNotExist:
            return Response({"message": "given content id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
    def patch(self, request, *args, **kwargs):
        data = request.data.copy()

        
       
        profile = User.objects.get(user=request.user.id)
        
        if 'about_me' not in data:
            data['about_me'] = profile.about_me
        if 'image' not in data:
            data['image'] = profile.image
        
        serializer = self.serializer_class(profile, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LearningSpaceApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = LearningSpaceSerializer
#     serializer_class2=LearningSpacePostSerializer
    
    
#     def get(self, request, *args, **kwargs):
#         try:
#             # learning_space_id = request.GET.get('id')
#             learning_space_id = request.user.id
#             print(learning_space_id)
#         except ValueError:
#             return Response(status=status.HTTP_400_BAD_REQUEST)

#         try:
#             ls = LearningSpace.objects.get(id=learning_space_id) 
#             serializer = self.serializer_class(ls)
#             return Response(serializer.data, status=status.HTTP_200_OK)
#         except LearningSpace.DoesNotExist:
#             return Response({"message": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
            
        

#     # TODO: add the owner to members of the created learning space
#     def post(self, request, *args, **kwargs):
#         '''
#         Create the Todo with given todo data
#         '''
      
#         data = request.data.copy()
#         data['ls_owner'] = request.user.id



#         serializer = self.serializer_class2(data=data)
#         if serializer.is_valid():
#             serializer.save()
#             ls = LearningSpace.objects.get(id=serializer.data['id'])
#             ls.members.add(request.user)
         
#             serializer = self.serializer_class2(ls)
#             return Response(serializer.data, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class CategoryView(APIView):
    # permission_classes = [permissions.IsAuthenticated] 
    def get(self, request):
        # user_token = request.COOKIES.get('access_token')
        # id = get_token_to_user(user_token)
        
        cate=Category.objects.all()
        serilizer = CategorySerializer(cate, many=True)
        contdata=[]
        for product in serilizer.data:
            cont_query = Content.objects.filter(categories_id=product['id']).order_by('-created_on')
            seri = ContentSerializer(cont_query,many = True)
            product['categorydata'] = seri.data
            contdata.append(product)
        
        return Response(contdata)
class CategoryList(APIView):
    # permission_classes = [permissions.IsAuthenticated] 
    def get(self, request):
        # user_token = request.COOKIES.get('access_token')
        # id = get_token_to_user(user_token)
        
        cate=Category.objects.all()
        serilizer = CategorySerializer(cate, many=True)
        
        return Response(serilizer.data)



class contentApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ContentSerializer
    def get(self, request, *args, **kwargs):
        content_id=request.user.id
        print(content_id)
        print('nayan')
        try:
            c = Content.objects.filter(owner=content_id).order_by('-created_on')
            serializer = ContentSerializer(c,many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Content.DoesNotExist:
            return Response({"message": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
        
    def post(self, request, *args, **kwargs):
        instance_data = request.data
        print(instance_data)
        data = {key: value for key, value in instance_data.items()}
        serializer = ContentSerializer(data=data)
   
        serializer.is_valid(raise_exception=True)
       
        instance = serializer.save()


        if request.FILES:
            photos = dict((request.FILES).lists()).get('image', None)
            print(photos)
            if photos:
                for photo in photos:
                    photo_data = {}
                    photo_data["content"] = instance.pk
                    photo_data["image"] = photo
                    photo_serializer = PhotoSerializer(data=photo_data)
                    photo_serializer.is_valid(raise_exception=True)
                    photo_serializer.save()

        return Response(serializer.data)



    def patch(self, request, *args, **kwargs):
        data = request.data.copy()

        try:
            content_id = data['id']
        except ValueError:
            return Response({"error": "given id is not an integer"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            content = Content.objects.get(id=content_id)
        except Content.DoesNotExist:
            return Response({"error": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

        if content.owner != request.user: 
            return Response({"error": "you are not the owner of this content"}, status=status.HTTP_400_BAD_REQUEST)       

        # Those fields are needed to validate data because Content exceptionally has a custom validate() function.
        
        if 'name' not in data:
            data['name'] = content.name
        if 'type' not in data:
            data['type'] = content.type
        if 'text' not in data:
            data['text'] = content.text
        if 'body' not in data:
            data['body'] = content.text
        if 'url' not in data:
            data['url'] = content.url
        if 'upVoteCount' not in data:
            data['upVoteCount'] = content.upVoteCount
        
        

        print(data)


        serializer = self.serializer_class(content, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class DeleteContentdata(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    def post(self,request):
        content_id=request.data['id']
        content_data = Content.objects.get(id = content_id)
        user_id= request.user.id
        print(user_id)
        content_content = Content.objects.filter(owner = user_id).filter(id=content_id)
        print(content_content)
        try:
            conten_photo = Photo.objects.filter(content=content_data)
            conten_photo.delete()
            content_content.delete()
            # content_content.save()

            response_msg = {'error': False}
    
        except:
            response_msg = {'error': True}
        return Response(response_msg)



# class DelateCarProduct(APIView):
#     authentication_classes = [TokenAuthentication, ]
#     permission_classes = [IsAuthenticated, ]

#     def post(self, request):
#         cart_product_id = request.data['id']
#         try:
#             cart_product_obj = CartProduct.objects.get(id=cart_product_id)
#             cart_cart = Cart.objects.filter(
#                 user=request.user).filter(isComplit=False).first()
#             cart_cart.total -= cart_product_obj.subtotal
#             cart_product_obj.delete()
#             cart_cart.save()
#             response_msg = {'error': False}
#         except:
#             response_msg = {'error': True}
#         return Response(response_msg)


# class DelateCart(APIView):
#     permission_classes = [IsAuthenticated, ]
#     authentication_classes = [TokenAuthentication, ]

#     def post(self, request):
#         cart_id = request.data['id']
#         try:
#             cart_obj = Cart.objects.get(id=cart_id)
#             cart_obj.delete()
#             response_msg = {'error': False}
#         except:
#             response_msg = {'error': True}
#         return Response(response_msg)


    




class contentListApiView(APIView):  
    # add permission to check if user is authenticated
    # permission_classes = [permissions.IsAuthenticated]
    # serializer_class = ContentSerializer
    def get(self, request, *args, **kwargs):
        # id=request.user.id
        try:
            # ls = ContentSerializer.objects.get(id=id)
            contents = Content.objects.all().order_by('-created_on')
            serializer = ContentSerializer(contents , many=True)
            return Response(serializer.data)
        except:
            return Response({"message": "given learning space id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

    # def get(self, request, *args, **kwargs):
    #     try:
    #         learning_space_id = request.user.id
    #         # learning_space_id = request.GET.get('learning_space_id')
    #         # learning_space_id=request.user.id
    #     except ValueError:
    #         return Response(status=status.HTTP_400_BAD_REQUEST)

    #     try:
    #         
    #         contents = Content.objects.all()
    #         serializer = self.serializer_class(contents, many=True)
    #         return Response(serializer.data)
    #     except ContentSerializer.DoesNotExist:
    #         return Response({"message": "given learning space id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)



# class PhotosApiView(APIView):
#     def get(self,request):
#         id=request.user.id


class enrollApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ContentSerializer

    def post(self, request, *args, **kwargs):
        try:
            learning_space_id = request.data.get('learning_space_id')
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            ls = ContentSerializer.objects.get(id=learning_space_id)
            ls.members.add(request.user)
            serializer = self.serializer_class(ls)

            return Response(serializer.data, status=status.HTTP_200_OK)
        except ContentSerializer.DoesNotExist:
            return Response({"message": "given learning space id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

class leaveApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ContentSerializer

    def post(self, request, *args, **kwargs):
        try:
            learning_space_id = int(request.data.get('learning_space_id'))
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            ls = Content.objects.get(id=learning_space_id)
            ls.members.remove(request.user)
            serializer = self.serializer_class(ls)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Content.DoesNotExist:
            return Response({"message": "given learning space id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)


class discussionApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DiscussionPostSerializer

    def post(self, request, *args, **kwargs):
        
        data = request.data.copy()
        

        data['owner'] = request.user.id
       

        # TODO: check wheter the given learning space id exists and user is a member of it

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class discussionApiListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DiscussionSerializer

    def get(self, request, *args, **kwargs):
        try:
            content_id = request.GET.get('content_id')
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            content = Content.objects.get(id=content_id)
            discussions = content.discussions.all()
            serializer = self.serializer_class(discussions, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Content.DoesNotExist:
            return Response({"message": "given content id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
        

class forgetpasswordApiView(APIView):
    # add permission to check if user is authenticated
    serializer_class = ResetSerializer

    def post(self, request, *args, **kwargs):
        try:
            
            get_email= request.data.copy()
            get_email=get_email["email"]
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        
        
        if not User.objects.filter(email=get_email).exists():
            return Response({"message": "given email doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
        else: 
            u= User.objects.get(email=get_email)
            new_pass=get_random_string(10)
            u.set_password(new_pass)
            u.save()
            #print(new_pass)
            #print(get_email)
            send_forget_password_mail(get_email, new_pass )
            return Response({"message": "your password is sent to your email"}, status=status.HTTP_200_OK)

class getuseridAPIView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer
    def get(self, request, *args, **kwargs):
        try:
            username = request.GET.get('username')
            user = User.objects.filter(username=username)[0]
            serializer = self.serializer_class(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response({"message": "User with given username doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

class userNamefromIDAPIView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer
    
    
    def get(self, request, *args, **kwargs):
        try:
            id = request.GET.get('id')
            user = User.objects.filter(id=id)[0]
            print(user)
            serializer = self.serializer_class(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response({"message": "User with given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)


class favoriteLearningSpaceAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FavoriteSerializer
    serializer_class_post = FavoritePostSerializer

    def get(self, request, *args, **kwargs):
        try:
            user_id = request.GET.get('user', request.user.id)

        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            favorite_ls = Favorite.objects.filter(user__id=user_id)
            serializer = self.serializer_class(favorite_ls, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except:
            return Response({"message": "given user id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

    
    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        data['user'] = request.user.id
        print(data)
        
        if Favorite.objects.filter(user=request.user.id, learningSpace=data['learningSpace']).exists():
            return Response({"message": "Already favorited this learning space"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class_post(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        
    
class disFavoriteAPIView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FavoriteSerializer

    def post(self, request, *args, **kwargs):
        try:
            learning_space_id = request.data.get('learningSpace')
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            favorite_record = Favorite.objects.get(learningSpace__id=learning_space_id)
            favorite_record.delete()
            serializer = self.serializer_class(favorite_record)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response({"message": "given learning space id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)












# class noteApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = NoteSerializer
#     serializer_class_post = NotePostSerializer

#     def post(self, request, *args, **kwargs):
        
#         data = request.data.copy()

#         data['owner'] = request.user.id
       

#         # TODO: check wheter the given learning space id exists and user is a member of it

#         serializer = self.serializer_class_post(data=data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)


#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#     def get(self, request, *args, **kwargs):
#         try:
#             # content_id = request.GET.get('content_id')
#             content_id=request.user.id
            
#         except ValueError:
#             return Response(status=status.HTTP_400_BAD_REQUEST)
#         try:  
#             note = Note.objects.filter(owner=request.user.id, content= content_id)
#             serializer = self.serializer_class(note, many=True)
#             return Response({"data": serializer.data}, status=status.HTTP_200_OK)
#         except LearningSpace.DoesNotExist:
#             return Response({"message": "given content id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)
    
#     def patch(self, request, *args, **kwargs):
#         data = request.data.copy()

#         try:
#             note_id = int(data['id'])
#         except ValueError:
#             return Response({"error": "given id is not an integer"}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             note = Note.objects.get(id=note_id)
#         except Note.DoesNotExist:
#             return Response({"error": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

#         if note.owner != request.user: 
#             return Response({"error": "you are not the owner of this note"}, status=status.HTTP_400_BAD_REQUEST)       

#         # Those fields are needed to validate data because Content exceptionally has a custom validate() function.
        
#         content_id=note.content.id
#         data['content'] = content_id
#         data['owner'] = note.owner
#         data['created_on'] = note.created_on

      

#         serializer = self.serializer_class(note, data=data, partial=True)

#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    





# class LearningSpaceListApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = LearningSpaceSerializer
    
    
#     def get(self, request, *args, **kwargs):
#         try:
#             ls = LearningSpace.objects.all()
#             serializer = self.serializer_class(ls, many=True)
#             return Response({"data": serializer.data}, status=status.HTTP_200_OK)
#         except LearningSpace.DoesNotExist:
#             return Response({"message": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

# class EnrolledLearningSpaceApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = LearningSpaceSerializer
    
    
#     def get(self, request, *args, **kwargs):
        
#         try:
#             ls=LearningSpace.objects.filter(members__id=request.user.id)
#             serializer = self.serializer_class(ls, many=True)
#             return Response({"data": serializer.data}, status=status.HTTP_200_OK)
#         except LearningSpace.DoesNotExist:
#             return Response({"message": "given user doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)



# class LearningSpaceSearchApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = LearningSpaceSerializer
    
    
#     def get(self, request, *args, **kwargs):
#         try:
#             search_parameter = request.GET.get('search_parameter')
#         except ValueError:
#             return Response(status=status.HTTP_400_BAD_REQUEST)

#         try:
#             ls = LearningSpace.objects.filter(name__icontains=search_parameter)
#             serializer = self.serializer_class(ls, many=True)
#             return Response({"data": serializer.data}, status=status.HTTP_200_OK)
#         except LearningSpace.DoesNotExist:
#             return Response({"message": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)



# class LearningSpaceTagSearchApiView(APIView):
#     # add permission to check if user is authenticated
#     permission_classes = [permissions.IsAuthenticated]
#     serializer_class = LearningSpaceSerializer
    
    
#     def get(self, request, *args, **kwargs):
#         try:
#             tag = request.GET.get('tag')
#         except ValueError:
#             return Response(status=status.HTTP_400_BAD_REQUEST)

#         try:
#             ls = LearningSpace.objects.filter(tag__icontains=tag)
#             serializer = self.serializer_class(ls, many=True)
#             return Response({"data": serializer.data}, status=status.HTTP_200_OK)
#         except LearningSpace.DoesNotExist:
#             return Response({"message": "given id doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

# Email: nayan1122@gmail.com