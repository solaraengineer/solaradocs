from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solaradocs', '0017_user_redirect_to_dashboard'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserApiToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('token_hash', models.CharField(db_index=True, max_length=64, unique=True)),
                ('token_prefix', models.CharField(help_text='First 10 chars of raw token, shown in UI for identification.', max_length=16)),
                ('access_level', models.CharField(choices=[('READ', 'Read only'), ('WRITE', 'Read + write + create'), ('DELETE', 'Read + write + create + delete')], default='READ', max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('project', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='api_tokens', to='solaradocs.project')),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='api_tokens', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['user', '-created_at'], name='solaradocs__user_id_api_tokens_idx')],
            },
        ),
    ]
