from typing import Annotated

from fastapi import Depends


def get_db():
    yield None


def get_current_user():
    return None


def get_current_superuser(user=Depends(get_current_user)):
    return user


CurrentUser = Annotated[dict, Depends(get_current_user)]
