from django.contrib import admin
from .models import  Content, Discussion, Photo,User, Favorite,Category


# Register your models here.
# admin.site.register(LearningSpace)
admin.site.register(Content)
admin.site.register(Discussion)
admin.site.register(User)
# admin.site.register(Profile)
admin.site.register(Photo)
admin.site.register(Category)
admin.site.register(Favorite)
# admin.site.register(Note)
