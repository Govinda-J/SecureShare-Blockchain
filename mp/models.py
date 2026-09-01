from django.db import models
from django.conf import settings


# ---- USER PROFILE ----
# Stores SecureShare-specific information linked to Django's built-in user.
class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile'
    )
    name = models.CharField(max_length=255)
    private_key = models.CharField(max_length=66, blank=True, null=True)

    def __str__(self):
        return self.name


# ---- ATTRIBUTE DEFINITIONS ----
# Stores the attribute names that can be used by SecureShare's access policies.
class AttributeKey(models.Model):
    """ Catalog of known attribute names. """
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.name


# ---- VERIFIED USER ATTRIBUTES ----
# Stores attributes that have been verified and assigned to a user by an admin.
class UserAttribute(models.Model):
    """ The verified, admin-assigned attributes for a user."""
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='attributes')
    key = models.CharField(max_length=100)
    value = models.CharField(max_length=255)

    class Meta:
        unique_together = ('profile', 'key')

    def __str__(self):
        return f"{self.profile.user.username}: {self.key}={self.value}"


# ---- ACTIVITY LOG ----
# Records application actions for user and admin activity pages.
# Keeping these events in Django avoids repeatedly querying blockchain logs.
class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('register', 'Registered'),
        ('upload', 'File Uploaded'),
        ('request_access', 'Requested File Access'),
        ('grant', 'Access Granted'),
        ('reject', 'Access Rejected'),
        ('revoke', 'Access Revoked'),
        ('download', 'File Downloaded'),
        ('request_attribute', 'Requested Attribute'),
        ('attribute_set', 'Attribute Set by Admin'),
        ('attribute_removed', 'Attribute Removed by Admin'),
        ('attribute_approved', 'Attribute Request Approved'),
        ('attribute_rejected', 'Attribute Request Rejected'),
        ('file_deleted', 'File Deleted'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='activity_log', null=True, blank=True,
        help_text='Whose personal activity feed this entry appears on.'
    )
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    detail = models.CharField(max_length=500)
    tx_hash = models.CharField(max_length=80, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} — {self.get_action_display()}: {self.detail}"


# ---- ATTRIBUTE REQUESTS ----
# Tracks requests from users who want an admin to verify a new attribute.
class AttributeRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='attribute_requests')
    key = models.CharField(max_length=100)
    value = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.profile.user.username} requested {self.key}={self.value} [{self.status}]"


# ---- FILE RECORDS ----
# Stores the Django-side record for each file managed by SecureShare.
# file_id is the SHA-256 hash of the filename and matches the on-chain file tag.
class File(models.Model):
    file_id = models.CharField(max_length=66, unique=True)  # sha256(filename) hex, matches on-chain file_tag
    file_name = models.CharField(max_length=255, blank=True, default='')
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='uploaded_files'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True, null=True)
    is_deleted = models.BooleanField(default=False)          
    deleted_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.file_name or self.file_id


# ---- FILE ACCESS SUBSCRIPTIONS ----
# Tracks which users currently have access to a file.
# user_keys stores the subscription keys used by the access polynomial.
class Subscription(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='subscriptions')
    user_id = models.CharField(max_length=150)  # username of the granted user
    user_keys = models.JSONField(default=list)
    user_names = models.JSONField(default=list)

    class Meta:
        unique_together = ('file', 'user_id')

    def __str__(self):
        return f"Subscription: file={self.file.file_id}, user={self.user_id}"


# ---- FILE ACCESS REQUESTS ----
# Records requests made by users to access protected files.
# The status tracks the request throughout its lifecycle.
class AccessRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('revoked', 'Revoked'),
    ]

    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='requests')
    request_id = models.CharField(max_length=66)
    requester_username = models.CharField(max_length=150)
    requester_address = models.CharField(max_length=42, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = ('file', 'request_id')

    def __str__(self):
        return f"{self.requester_username} -> {self.file.file_name} [{self.status}]"