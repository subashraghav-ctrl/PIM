from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.user import User


def has_permission(user: "User", resource: str, action: str) -> bool:
    """Check if a user has a specific resource:action permission via any of their roles."""
    for role in user.roles:
        for perm in role.permissions:
            if perm.resource == resource and perm.action == action:
                return True
            # Wildcard: action "admin" grants all actions on a resource
            if perm.resource == resource and perm.action == "admin":
                return True
    return False


def get_effective_permissions(user: "User") -> list[dict]:
    """Return flattened list of all unique permissions across all roles."""
    seen: set[str] = set()
    result = []
    for role in user.roles:
        for perm in role.permissions:
            if perm.name not in seen:
                seen.add(perm.name)
                result.append({
                    "id": str(perm.id),
                    "name": perm.name,
                    "resource": perm.resource,
                    "action": perm.action,
                    "description": perm.description,
                    "via_role": role.name,
                })
    return result
