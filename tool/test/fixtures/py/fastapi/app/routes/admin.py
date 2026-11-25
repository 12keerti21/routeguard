from fastapi import APIRouter, Depends

from app.deps import get_current_superuser

router = APIRouter(prefix="/admin", dependencies=[Depends(get_current_superuser)])


@router.get("/users/{user_id}")
def admin_user(user_id: int):
    return {}
