"""AWS Lambda entrypoint (API Gateway HTTP API -> Mangum -> FastAPI)."""
from mangum import Mangum

from .main import app

handler = Mangum(app, lifespan="off")
