from fastapi import APIRouter, HTTPException, status

from app.dependencies import CurrentUser, DbSession
from app.models import ElementName
from app.schemas import OrderRequest
from app.services import MOCK_ORDERS, has_permission, require_permission


router = APIRouter(prefix="/resources/orders", tags=["Orders"])


@router.get("")
def list_orders(current_user: CurrentUser, db: DbSession) -> list[dict]:
    require_permission(db, current_user.id, ElementName.orders.value, "read_permission")
    if has_permission(db, current_user.id, ElementName.orders.value, "read_all_permission"):
        return MOCK_ORDERS
    return [order for order in MOCK_ORDERS if order["owner_email"] == current_user.email]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_order(data: OrderRequest, current_user: CurrentUser, db: DbSession) -> dict:
    require_permission(db, current_user.id, ElementName.orders.value, "create_permission")
    order = {
        "id": max((order["id"] for order in MOCK_ORDERS), default=0) + 1,
        "title": data.title,
        "amount": data.amount,
        "owner_email": current_user.email,
    }
    MOCK_ORDERS.append(order)
    return order


@router.patch("/{order_id}")
def update_order(order_id: int, data: OrderRequest, current_user: CurrentUser, db: DbSession) -> dict:
    order = next((item for item in MOCK_ORDERS if item["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    allowed = has_permission(db, current_user.id, ElementName.orders.value, "update_all_permission") or (
        order["owner_email"] == current_user.email
        and has_permission(db, current_user.id, ElementName.orders.value, "update_permission")
    )
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    order.update(title=data.title, amount=data.amount)
    return order


@router.delete("/{order_id}")
def delete_order(order_id: int, current_user: CurrentUser, db: DbSession) -> dict[str, str]:
    order = next((item for item in MOCK_ORDERS if item["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    allowed = has_permission(db, current_user.id, ElementName.orders.value, "delete_all_permission") or (
        order["owner_email"] == current_user.email
        and has_permission(db, current_user.id, ElementName.orders.value, "delete_permission")
    )
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    MOCK_ORDERS.remove(order)
    return {"message": "Order deleted"}
