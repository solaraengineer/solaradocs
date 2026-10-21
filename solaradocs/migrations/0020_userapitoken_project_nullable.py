from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('solaradocs', '0019_rename_solaradocs__user_id_api_tokens_idx_solaradocs__user_id_05f151_idx_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userapitoken',
            name='project',
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='api_tokens',
                to='solaradocs.project',
            ),
        ),
    ]
