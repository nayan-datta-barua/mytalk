# from django.urls import path
# from .views import CategoryView, BlogsViewSet, PostApiview, MyTokenObtainPairView, UserDataView, RegistrationAPIView, VerifyOTPAPIView, LogoutBlacklistTokenUpdateView, DemoView, DemoView2, MyTokenObtainPairView
# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
# )

# urlpatterns = [

#     path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
#     # path('login/', LoginTokenGenerationAPIView.as_view(), name='token_obtain_pair'),
#     path('verify/', VerifyOTPAPIView.as_view(), name='verify-otp'),
#     path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
#     path('logout/', LogoutBlacklistTokenUpdateView.as_view(), name='logout'),
#     path('register/', RegistrationAPIView.as_view(), name='registration'),
#     path('experiment/',DemoView.as_view(),name='demo'),
#     path('experiment2/',DemoView2.as_view(),name='demo2'),
#     path('userdata/',UserDataView.as_view(),),
# 	path('PostApiview/', PostApiview.as_view()),
# 	path('postdata/', BlogsViewSet.as_view()),
# 	path('category/', CategoryView.as_view()),

# ]



from django.urls import path

from django.urls import path
from .views import *


urlpatterns = [
    path('category/', CategoryView.as_view()),
    path('categorylist/', CategoryList.as_view()),
    path('register/',UserRegistrationView.as_view(),name="register"),
    path('login/',UserLoginView.as_view(),name="login"),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
#     path('login/', UserLoginAPIView.as_view(), name='token_obtain_pair'),
# #     # path('login/', LoginTokenGenerationAPIView.as_view(), name='token_obtain_pair'),
#     path('verify/', VerifyOTPAPIView.as_view(), name='verify-otp'),
#     # path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
#     path('logout/', LogoutBlacklistTokenUpdateView.as_view(), name='logout'),
#     path('register/', UserRegistrationAPIView.as_view(), name='registration'),
    # path('app/register/', Register.as_view(), name='register'),
    # path('app/login/', Login.as_view(), name='login'),
    # path('app/logout/', knox_views.LogoutView.as_view(), name='logout'),
    # path('app/logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),
    # path('change-password/', ChangePassword.as_view(), name='change-password'),
    # path('learning-space/', LearningSpaceApiView.as_view(), name='learning-space'),
    path('content/', contentApiView.as_view(), name='content'),
    path('contentdelete/', DeleteContentdata.as_view(), name='contentdelete'),
    path('content-list/', contentListApiView.as_view(), name='content-list'),
    path('enroll/', enrollApiView.as_view(), name='enroll'),
    path('discussion/', discussionApiView.as_view(), name='discussion'),
    path('discussion-list/', discussionApiListView.as_view(), name='discussion-list'),
    path('userdata/', profileApiView.as_view(), name='profile'),
    # path('learning-space-list/', LearningSpaceListApiView.as_view(), name='learning-space-list'),
    # path('learning-space-search/', LearningSpaceSearchApiView.as_view(), name='learning-space-search'),
    # path('learning-space-tag-search/', LearningSpaceTagSearchApiView.as_view(), name='learning-space-tag-search'),
    path('forget-password/' , forgetpasswordApiView.as_view() , name="forget_password"),
    path('leave-learning-space/', leaveApiView.as_view(), name='leave-learning-space'),
    # path('enrolled-learning-spaces/', EnrolledLearningSpaceApiView.as_view(), name='enrolled-learning-spaces'),
    # path('note/', noteApiView.as_view(), name='note'),
    path(' /', getuseridAPIView.as_view(), name='user_id_from_username'),
    path('user-from-id/', userNamefromIDAPIView.as_view(), name='user-from-id'),
    path('favorite/', favoriteLearningSpaceAPIView.as_view(), name='favorite'),
    path('unfavorite/', disFavoriteAPIView.as_view(), name='unfavorite'),
    
    
    


]