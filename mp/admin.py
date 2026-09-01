from django.contrib import admin
from mp import models


class UserAttributeInline(admin.TabularInline):
    model = models.UserAttribute
    extra = 1


class ProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'private_key')
    search_fields = ('name', 'user__username')
    inlines = [UserAttributeInline]


class AttributeRequestAdmin(admin.ModelAdmin):
    list_display = ('profile', 'key', 'value', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('profile__user__username', 'key', 'value')


admin.site.register(models.Profile, ProfileAdmin)
admin.site.register(models.AttributeKey)
admin.site.register(models.AttributeRequest, AttributeRequestAdmin)
admin.site.register(models.File)
admin.site.register(models.Subscription)
admin.site.register(models.AccessRequest)
