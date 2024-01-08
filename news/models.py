from django.db import models
from django.contrib.auth.models import User
from django.core.cache import cache
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.db.models import Sum
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class UserManager(BaseUserManager):

    
    def create_user(self, email, user_name, password, **other_fields):

        if not email:
            raise ValueError("Provide email")
        email = self.normalize_email(email)
        user = self.model(email=email, user_name=user_name, **other_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, user_name, password, **other_fields):
        other_fields.setdefault('is_staff',True)
        other_fields.setdefault('is_superuser',True)
        other_fields.setdefault('is_active',True)

        if other_fields.get('is_staff') is not True:
            raise ValueError('staff privilege must be assigned to superuser')
        if other_fields.get('is_superuser') is not True:
            raise ValueError('superuser privilege must be assigned to superuser')

        return self.create_user(email, user_name, password,**other_fields)


class User(AbstractBaseUser,PermissionsMixin):

    email = models.EmailField(
      verbose_name='Email',
      max_length=255,
      unique=True,)
    user_name = models.CharField(max_length=100, unique=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    rating = models.SmallIntegerField(default=0)
    about_me = models.CharField(max_length=100)
    image = models.ImageField(default='images/person.png', upload_to='images/',null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name']
    
    def __str__(self):
        return self.user_name
    
    def update_rating(self):
        prt = self.post_set.aggregate(post_rating=Sum('rating'))
        post_rt = 0
        post_rt += prt.get('post_rating') if prt.get('post_rating') else 0

        crt = self.user.comment_set.aggregate(comment_rating=Sum('rating'))
        comment_rt = 0
        comment_rt += crt.get('comment_rating') if crt.get('comment_rating') else 0

        self.rating = post_rt * 3 + comment_rt
        self.save()


class Category(models.Model):
    category = models.CharField(max_length=20)
    category_image = models.ImageField(upload_to='uploads/',null=True)
    # userCategory = models.ManyToManyField(User,through='UserCategory')


    def __str__(self):
        return f'{self.category}'
        # return f'{self.get_category_display()}'


class UserCategory(models.Model):
    userSubscribe = models.ForeignKey(User, on_delete=models.CASCADE)
    categorySubscribe = models.ForeignKey(Category, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.userSubscribe} ~ {self.categorySubscribe}'


class Content(models.Model):
    POSTS = [
        ('N', gettext_lazy('News')),
        ('A', gettext_lazy('Article')),
    ]
    name = models.CharField(max_length=30)
    title = models.TextField(max_length=200)
    categories = models.ForeignKey(Category,on_delete=models.CASCADE)
    body = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owner')
    post = models.CharField(gettext_lazy('post'), max_length=1, choices=POSTS, default='N')
    upVoteCount = models.IntegerField(default=0)

class Photo(models.Model):
    content = models.ForeignKey(Content, on_delete=models.CASCADE)
    image=models.FileField(blank=True,upload_to='content_file_name/')
    

class Discussion(models.Model):
    content = models.ForeignKey(Content,on_delete=models.CASCADE, related_name='discussions')
    #name = models.CharField(max_length=30)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    body = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True)
    rating = models.SmallIntegerField(default=0)


    def __str__(self):
        _of = gettext_lazy("of")
        _from = gettext_lazy("from")
        _with = gettext_lazy("with rating")

        return f'{self.content} {_of} {self.owner.id} {_from} '\
                  + f'{self.created_on.strftime("%d-%m-%y")} {_with} {self.rating}'

    def like(self):
        self.rating += 1
        self.save()

    def dislike(self):
        self.rating -= 1
        self.save()

    def date_in(self):
        return self.time_in.date()


    class Meta:
        ordering = ['created_on']

#    def __str__(self):
#        return 'Comment {} by {}'.format(self.body, self.owner.username)



class Favorite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    learningSpace = models.ForeignKey(Content, on_delete=models.CASCADE)

