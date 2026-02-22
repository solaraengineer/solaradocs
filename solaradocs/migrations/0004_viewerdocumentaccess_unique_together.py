# Generated manually

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('solaradocs', '0003_viewerdocumentaccess'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='viewerdocumentaccess',
            unique_together={('project', 'document')},
        ),
    ]
