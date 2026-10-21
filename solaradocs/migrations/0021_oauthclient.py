from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solaradocs', '0020_userapitoken_project_nullable'),
    ]

    operations = [
        migrations.CreateModel(
            name='OAuthClient',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('client_id', models.CharField(db_index=True, max_length=64, unique=True)),
                ('client_name', models.CharField(blank=True, max_length=200)),
                ('redirect_uris', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
