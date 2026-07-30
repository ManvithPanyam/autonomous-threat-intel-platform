from fastapi import Header, HTTPException, status

class UserContext:
    def __init__(self, user_id: str, role: str):
        self.user_id = user_id
        self.role = role.lower()

def get_current_user(
    x_user_id: str = Header(default="analyst_default", alias="X-User-ID"),
    x_user_role: str = Header(default="analyst", alias="X-User-Role"),
) -> UserContext:
    """
    Parses RBAC user context from request headers.
    Roles: admin, analyst, readonly.
    """
    return UserContext(user_id=x_user_id, role=x_user_role)

def require_analyst_or_admin(
    x_user_role: str = Header(default="analyst", alias="X-User-Role"),
    x_user_id: str = Header(default="analyst_default", alias="X-User-ID"),
) -> UserContext:
    role = x_user_role.lower()
    if role not in ["analyst", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: Role '{x_user_role}' is not authorized to perform action approval or denial.",
        )
    return UserContext(user_id=x_user_id, role=role)
