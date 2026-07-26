"""
Skill Library UI — a browsable, read-only reference of framework-mapped
cybersecurity SOPs (see app/skill_library.py). Two pages: a searchable list and
a rendered detail. No model involvement; content is fetched live from GitHub and
cached in-process.
"""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import config, skill_library

log = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "web" / "templates"))


def _disabled(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "skills.html",
        {
            "app_name": config.APP_NAME,
            "nav": "skills",
            "skills": [],
            "error": "The Skill Library is turned off (SKILLS_LIBRARY_ENABLED=0).",
            "repo_url": config.SKILLS_REPO_HTML_BASE,
        },
    )


@router.get("/skills")
def skills_list(request: Request):
    if not config.SKILLS_LIBRARY_ENABLED:
        return _disabled(request)
    error = None
    skills: list[dict] = []
    try:
        skills = skill_library.list_skills()
    except skill_library.SkillLibraryError as e:
        log.warning("Skill Library index unavailable: %s", e)
        error = str(e)
    return templates.TemplateResponse(
        request,
        "skills.html",
        {
            "app_name": config.APP_NAME,
            "nav": "skills",
            "skills": skills,
            "error": error,
            "repo_url": config.SKILLS_REPO_HTML_BASE,
        },
    )


@router.get("/skills/{name}")
def skill_detail(request: Request, name: str):
    if not config.SKILLS_LIBRARY_ENABLED:
        return _disabled(request)
    try:
        skill = skill_library.get_skill(name)
    except KeyError:
        return templates.TemplateResponse(
            request,
            "skill_detail.html",
            {
                "app_name": config.APP_NAME,
                "nav": "skills",
                "skill": None,
                "error": f"No skill named '{name}'.",
                "repo_url": config.SKILLS_REPO_HTML_BASE,
            },
            status_code=404,
        )
    except skill_library.SkillLibraryError as e:
        log.warning("Skill '%s' unavailable: %s", name, e)
        return templates.TemplateResponse(
            request,
            "skill_detail.html",
            {
                "app_name": config.APP_NAME,
                "nav": "skills",
                "skill": None,
                "error": str(e),
                "repo_url": config.SKILLS_REPO_HTML_BASE,
            },
        )
    return templates.TemplateResponse(
        request,
        "skill_detail.html",
        {
            "app_name": config.APP_NAME,
            "nav": "skills",
            "skill": skill,
            "error": None,
            "repo_url": config.SKILLS_REPO_HTML_BASE,
        },
    )
