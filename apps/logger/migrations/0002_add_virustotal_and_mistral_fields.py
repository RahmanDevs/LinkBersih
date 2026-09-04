from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('logger', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanlog',
            name='virustotal_analysis_detail',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='mistral_analysis_detail',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
