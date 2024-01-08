from django.conf import settings
from datetime import datetime, timedelta
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import request
from django.contrib.auth import get_user_model
import jwt


def generate_access_token(user):
	payload = {
		'user_id': user.user_id,
		'exp': datetime.now() + timedelta(days=1, minutes=0),
		'iat': datetime.now(),
	}

	access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
	return access_token




def get_token_to_user(user_token):
		

		if not user_token:
			raise AuthenticationFailed('Unauthenticated user.')

		payload = jwt.decode(user_token, settings.SECRET_KEY, algorithms=['HS256'])
		# user=payload['user_id']
		# print(payload['user_id'])
		user_model = get_user_model()
		# user_model = User
		user = user_model.objects.filter(user_id=payload['user_id']).first()
		user=user.user_id
		return user




from django.core.mail import EmailMessage
import os

class Util:
  @staticmethod
  def send_email(data):
    email = EmailMessage(
      subject=data['subject'],
      body=data['body'],
      from_email=os.environ.get('EMAIL_FROM'),
      to=[data['to_email']]
    )
    email.send()