from __future__ import annotations

from typing import Dict, Any, List
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse


def get_multi_framework_router() -> APIRouter:
    """
    Simulates multi-framework conventions across Django REST, Spring Boot, and Laravel
    to benchmark cross-framework generalization.
    """
    router = APIRouter(prefix="/frameworks", tags=["Multi-Framework"])

    # 1. Django REST Framework Convention
    @router.get("/django/api/v1/users/")
    async def django_users_view(format: str = "json", search: str = ""):
        if "'" in search:
            return JSONResponse(
                status_code=500,
                content={"error": "django.db.utils.OperationalError: syntax error at or near \"'\""}
            )
        return JSONResponse({"count": 1, "results": [{"id": 1, "username": "django_admin"}]})

    # 2. Spring Boot Actuator & REST Convention
    @router.get("/spring/actuator/env")
    async def spring_actuator_env():
        return JSONResponse({
            "activeProfiles": ["production"],
            "propertySources": [
                {"name": "systemEnvironment", "properties": {"SPRING_DATASOURCE_PASSWORD": {"value": "******"}}}
            ]
        })

    @router.get("/spring/api/orders/{order_id}")
    async def spring_order_view(order_id: str):
        if "../" in order_id or "..\\" in order_id:
            return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\n[boot loader]", status_code=200)
        return JSONResponse({"orderId": order_id, "status": "SHIPPED"})

    # 3. Laravel REST Convention
    @router.get("/laravel/api/products")
    async def laravel_products_view(filter: str = ""):
        if "<script>" in filter or "<scout_xss_marker_1>" in filter:
            return PlainTextResponse(f"<div>Results for: {filter}</div>", status_code=200, media_type="text/html")
        return JSONResponse({"data": [{"id": 101, "name": "Laravel Item"}]})

    return router
