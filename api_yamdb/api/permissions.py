from rest_framework import permissions

from api_yamdb.settings import ADMIN, MODERATOR

class IsAdminUserPermission(permissions.BasePermission):
    message = {'detail': 'Недостаточно прав доступа'}

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.role == ADMIN
            or request.user.is_staff
            or request.user.is_superuser
        )


class ReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class IsModerUserPermission(permissions.BasePermission):
    message = {'detail': 'Недостаточно прав доступа'}

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.role == MODERATOR
        )

class IsOwnerOrReadOnly(permissions.BasePermission):
    message = {'detail': 'Недостаточно прав доступа'}

    def has_permission(self, request, view):
        return request.method == 'PATCH'
    
    def has_object_permission(self, request, view, obj):
        print(obj.author == request.user)
        return obj.author == request.user
    

class CreateCommentOrRewiewPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.method in permissions.SAFE_METHODS
            or request.user.is_authenticated
        )

    def has_object_permission(self, request, view, obj):
        return (
            request.method in permissions.SAFE_METHODS
            or (
                request.user.is_authenticated
                and (
                    obj.author == request.user
                    or request.user.role == MODERATOR
                    or request.user.role == ADMIN
                    or request.user.is_staff
                    or request.user.is_superuser
                )
            )
        )

