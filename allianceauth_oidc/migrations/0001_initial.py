# Generated by Django 4.0.10 on 2023-07-16 11:41

import oauth2_provider.generators
import oauth2_provider.models

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('authentication', '0020_userprofile_language_userprofile_night_mode'),
    ]

    run_before = [
        ('oauth2_provider', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AllianceAuthApplication',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('client_id', models.CharField(db_index=True,
                 default=oauth2_provider.generators.generate_client_id, max_length=100, unique=True)),
                ('redirect_uris', models.TextField(blank=True,
                 help_text='Allowed URIs list, space separated')),
                ('post_logout_redirect_uris', models.TextField(blank=True,
                 help_text='Allowed Post Logout URIs list, space separated')),
                ('client_type', models.CharField(choices=[
                 ('confidential', 'Confidential'), ('public', 'Public')], max_length=32)),
                ('authorization_grant_type', models.CharField(choices=[('authorization-code', 'Authorization code'), ('implicit', 'Implicit'), (
                    'password', 'Resource owner password-based'), ('client-credentials', 'Client credentials'), ('openid-hybrid', 'OpenID connect hybrid')], max_length=32)),
                ('client_secret', oauth2_provider.models.ClientSecretField(blank=True, db_index=True,
                 default=oauth2_provider.generators.generate_client_secret, help_text='Hashed on Save. Copy it now if this is a new secret.', max_length=255)),
                ('name', models.CharField(blank=True, max_length=255)),
                ('skip_authorization', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('algorithm', models.CharField(blank=True, choices=[('', 'No OIDC support'), (
                    'RS256', 'RSA with SHA-2 256'), ('HS256', 'HMAC with SHA-2 256')], default='', max_length=5)),
                ('logo', models.ImageField(blank=True, null=True, upload_to='')),
                ('groups', models.ManyToManyField(blank=True, to='auth.group')),
                ('states', models.ManyToManyField(
                    blank=True, to='authentication.state')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                 related_name='%(app_label)s_%(class)s', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
