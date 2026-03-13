"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
@router.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "tracemark",
        "version": "0.1.0-mvp",
    }
