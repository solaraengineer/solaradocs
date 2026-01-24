from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    Tier = models.CharField('Tier', max_length=20, default='free')
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)
    subscription_status = models.CharField(max_length=50, default='none')


TIER_LIMITS = {
    'free': {'projects': 1, 'documents': 2, 'teams': 1, 'members': 3, 'backups': False, 'audit': False,
             'pending': False},
    'student': {'projects': 3, 'documents': 5, 'teams': 2, 'members': 6, 'backups': True, 'audit': False,
                'pending': False},
    'team': {'projects': 5, 'documents': 20, 'teams': 5, 'members': 20, 'backups': True, 'audit': True,
             'pending': True},
    'enterprise': {'projects': None, 'documents': None, 'teams': None, 'members': None, 'backups': True, 'audit': True,
                   'pending': True},
}

TEAM_ROLES = [
    ('EDITOR', 'Editor'),
    ('ADMIN', 'Admin'),
]


class Project(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_projects')
    project_name = models.CharField(max_length=255)
    people = models.TextField(blank=True)
    content = models.TextField(blank=True)
    backups_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    documents = models.IntegerField(default=1)
    tier = models.CharField(max_length=12, default='free')

    def __str__(self):
        return self.project_name


class Teams(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='project_teams')
    team_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.team_name} - {self.project.project_name}"


class TeamMember(models.Model):
    team = models.ForeignKey(Teams, on_delete=models.CASCADE, related_name='team_members')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_teams')
    role = models.CharField(max_length=10, choices=TEAM_ROLES, default='EDITOR')
    can_direct_save = models.BooleanField(default=False)  # If True, saves directly; if False, changes go to pending review
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('team', 'user')

    def __str__(self):
        return f"{self.user.username} - {self.team.team_name} ({self.role})"


class Documents(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='project_documents')
    document_name = models.CharField(max_length=255)
    content = models.TextField(blank=True, default='')
    team_assigned = models.ForeignKey(Teams, on_delete=models.CASCADE, related_name='team_documents')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.document_name} - {self.project.project_name}"


class Audit(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='project_audits')
    document = models.ForeignKey(Documents, on_delete=models.CASCADE, null=True, blank=True, related_name='document_audits')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_audits')
    action = models.CharField(max_length=50, default='edit')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} {self.action} {self.document.document_name if self.document else 'N/A'}"


class Pending(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='pendings')
    team = models.ForeignKey(Teams, on_delete=models.CASCADE, related_name='team_pendings')
    document = models.ForeignKey(Documents, on_delete=models.CASCADE, related_name='document_pendings')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_pendings')
    submitted_content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    note = models.TextField(blank=True)

    def __str__(self):
        return f"Pending by {self.user.username} on {self.project.project_name}"


class Contributor(models.Model):
    ROLE_CHOICES = [
        ('VIEWER', 'Viewer'),
        ('EDITOR', 'Editor'),
        ('ADMIN', 'Admin'),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='contributors')
    username = models.CharField(max_length=255)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='VIEWER')
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('project', 'username')

    def __str__(self):
        return f"{self.username} - {self.project.project_name} ({self.role})"


class Backup(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='backups')
    document = models.ForeignKey(Documents, on_delete=models.CASCADE, related_name='document_backups')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.project.project_name} - {self.created_at}"


class PendingAction(models.Model):
    """
    Tracks actions taken on pending edits (accept/reject).
    Provides audit trail: "USER X ACCEPTED/REJECTED PENDING FROM Z AT {DATETIME}"
    """
    ACTION_CHOICES = [
        ('accept', 'Accepted'),
        ('reject', 'Rejected'),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='pending_actions')
    document = models.ForeignKey(Documents, on_delete=models.SET_NULL, null=True, blank=True, related_name='pending_actions')
    pending_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='submitted_pendings')  # User who submitted the pending edit
    actioned_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='actioned_pendings')  # User who accepted/rejected
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    document_name = models.CharField(max_length=255)  # Store document name in case document is deleted
    pending_note = models.TextField(blank=True)  # The note from the original pending submission
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.actioned_by.username} {self.action} pending from {self.pending_user.username} at {self.created_at}"


class Changelog(models.Model):
    VERSION_TYPES = [
        ('major', 'Major'),
        ('minor', 'Minor'),
        ('patch', 'Patch'),
    ]

    version = models.CharField(max_length=20)
    title = models.CharField(max_length=255)
    description = models.TextField()
    version_type = models.CharField(max_length=10, choices=VERSION_TYPES, default='minor')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"v{self.version} - {self.title}"