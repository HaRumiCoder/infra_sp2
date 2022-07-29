# Generated by Django 2.2.16 on 2022-05-22 13:58

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reviews', '0011_auto_20220521_1307'),
    ]

    operations = [
        migrations.AlterField(
            model_name='review',
            name='score',
            field=models.PositiveSmallIntegerField(validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(10)], verbose_name='Оценка'),
        ),
        migrations.AlterField(
            model_name='title',
            name='description',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='title',
            name='name',
            field=models.TextField(),
        )
    ]