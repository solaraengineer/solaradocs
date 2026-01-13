from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    Tier = models.CharField('Tier', max_length=20, default='Free')


class Project(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_projects')
    project_name = models.CharField(max_length=255)
    content = models.TextField(default='Welcome to solaradocs')
    people = models.TextField(blank=True)
    backups_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.project_name


class Backup(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='backups')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='backups')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.project_name} - {self.created_at}"

class Contributor(models.Model):
    ROLE_CHOICES = [
        ('VIEWER', 'Viewer'),
        ('EDITOR', 'Editor'),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='contributors')
    username = models.CharField(max_length=255)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='VIEWER')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('project', 'username')

    def __str__(self):
        return f"{self.username} - {self.project.project_name} ({self.role})"

class Pending(models.Model):
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='pendings'
    )

    username = models.CharField(max_length=255)
    submitted_content = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Pending by {self.username} on {self.project.project_name}"