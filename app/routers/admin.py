from fastapi import APIRouter
from sqlalchemy import select

from app.dependencies import CurrentUser, DbSession
from app.models import AccessRoleRule, BusinessElement, ElementName, Role, RoleName
from app.schemas import RuleUpdateRequest
from app.services import PERMISSIONS, find_element, find_role, require_permission


router = APIRouter(prefix="/admin/rules", tags=["Administration"])


@router.get("")
def list_rules(current_user: CurrentUser, db: DbSession) -> list[dict]:
    require_permission(db, current_user.id, ElementName.access_rules.value, "read_all_permission")
    rows = db.execute(
        select(AccessRoleRule, Role.name, BusinessElement.name)
        .join(Role, Role.id == AccessRoleRule.role_id)
        .join(BusinessElement, BusinessElement.id == AccessRoleRule.element_id)
        .order_by(Role.name, BusinessElement.name)
    ).all()
    return [
        {
            "role": role_name,
            "element": element_name,
            **{permission: getattr(rule, permission) for permission in PERMISSIONS},
        }
        for rule, role_name, element_name in rows
    ]


@router.put("/{role_name}/{element_name}")
def update_rule(
    role_name: RoleName,
    element_name: ElementName,
    data: RuleUpdateRequest,
    current_user: CurrentUser,
    db: DbSession,
) -> dict:
    require_permission(db, current_user.id, ElementName.access_rules.value, "update_all_permission")
    role = find_role(db, role_name.value)
    element = find_element(db, element_name.value)
    rule = db.get(AccessRoleRule, (role.id, element.id))
    values = data.model_dump()
    for name, value in values.items():
        setattr(rule, name, value)
    db.commit()
    return {"role": role_name.value, "element": element_name.value, **values}
