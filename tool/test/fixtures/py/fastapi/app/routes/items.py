import httpx
from fastapi import APIRouter, Depends

from app.deps import CurrentUser, get_db
from app.models import Item

router = APIRouter(prefix="/items", tags=["items"])


# vulnerable: no owner check
@router.get("/{item_id}")
def read_item(item_id: int, user: CurrentUser, session=Depends(get_db)):
    return session.get(Item, item_id)


# safe: compared with the caller
@router.delete("/{item_id}")
def delete_item(item_id: int, user: CurrentUser, session=Depends(get_db)):
    item = session.get(Item, item_id)
    if item.owner_id != user.id:
        raise HTTPException(status_code=403)
    session.delete(item)


# public on purpose
@router.get("/public/list")
def list_public():
    return []


# vulnerable: fetches a URL the client sends
@router.get("/fetch/remote")
def fetch(url: str, user: CurrentUser):
    return httpx.get(url).text
