"""FastAPI application factory and static-file serving."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from WiFiCatcher import __version__
from WiFiCatcher.api import router

WEB_DIR = Path(__file__).parent / "web"


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    # Graceful shutdown (Enter / Ctrl+C / the /api/shutdown route): stop any live
    # capture so airodump-ng is killed and the interface is restored to managed
    # mode, then restart NetworkManager so normal Wi-Fi resumes.
    import asyncio

    try:
        from WiFiCatcher.api.routes import CAPTURE
        await CAPTURE.stop()
    except Exception:
        pass
    # The app is unprivileged, so the actual restart runs in the root helper.
    # The helper only (re)starts NetworkManager if it is currently down, so a
    # session that never captured leaves a working connection untouched.
    try:
        from WiFiCatcher.privileged.client import PrivClient
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: PrivClient().call("network.restart"))
    except Exception:
        pass


def create_app() -> FastAPI:
    app = FastAPI(title="WiFiCatcher", version=__version__, lifespan=_lifespan)
    app.include_router(router)

    app.mount(
        "/static",
        StaticFiles(directory=str(WEB_DIR / "static")),
        name="static",
    )

    @app.get("/")
    def index():
        # no-cache so the browser always revalidates the page — and picks up the
        # versioned app.js / style.css links it carries — instead of showing a
        # stale build from cache after an update.
        return FileResponse(
            str(WEB_DIR / "index.html"),
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        # Serve the icon for browsers that request /favicon.ico at the site root.
        # no-cache so a refreshed icon is picked up instead of a stale cached one.
        return FileResponse(
            str(WEB_DIR / "static" / "img" / "favicon.ico"),
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
