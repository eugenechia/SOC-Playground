"""
Workbench — pick a task (framing) + a downloaded model, then chat/experiment.

Chat streams via a POST + SSE frames (token/done). Because EventSource cannot
issue a POST, the browser reads the streamed body with fetch()+getReader()
(see web/static/chat.js). The model runs on a background thread inside
runtime.generate_stream, so the event loop is never blocked.

Phase-2 seam: today this calls generate_stream once (pure chat). When tasks gain
tools, the single call below becomes an agent loop (stream -> detect tool call
-> tool.run() -> feed result back -> continue), publishing steps over the same
SSE contract. Nothing else in this module needs to change.
"""
import json
import secrets as pysecrets

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from agents.loop import run_agent
from app import config, sessions
from integrations import crowdstrike
from models_engine import registry
from models_engine.inference import InferenceError, runtime
from models_engine.tasks import get_task, list_tasks, resolve_tools

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "web" / "templates"))


def _sid(request: Request) -> str:
    sid = request.session.get("sid")
    if not sid:
        sid = pysecrets.token_hex(8)
        request.session["sid"] = sid
    return sid


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@router.get("/workbench")
def workbench_page(request: Request, task: str = "", model: str = ""):
    tasks = list_tasks()
    ready_models = [m for m in registry.scan() if m.status == "ready"]

    selected_task = get_task(task) or (tasks[0] if tasks else None)
    model_ids = [m.model_id for m in ready_models]
    selected_model = model if model in model_ids else (model_ids[0] if model_ids else "")

    history = []
    if selected_task and selected_model:
        history = sessions.get_history(_sid(request), selected_task.id, selected_model)

    return templates.TemplateResponse(
        request,
        "workbench.html",
        {
            "app_name": config.APP_NAME,
            "nav": "workbench",
            "tasks": tasks,
            "models": ready_models,
            "selected_task": selected_task,
            "selected_model": selected_model,
            "history": history,
        },
    )


@router.post("/workbench/chat")
def workbench_chat(
    request: Request,
    task: str = Form(...),
    model: str = Form(...),
    message: str = Form(...),
):
    sid = _sid(request)
    task_obj = get_task(task)
    if task_obj is None:
        return StreamingResponse(
            iter([_sse("error", {"message": "Unknown task."})]),
            media_type="text/event-stream",
        )

    system_prompt = task_obj.system_prompt
    history = sessions.get_history(sid, task, model)
    sessions.append(sid, task, model, "user", message)

    # Resolve the task's tools (fail-closed killswitch). If a tools-task's
    # integration isn't configured, fall back to plain chat with a note.
    tools = resolve_tools(task_obj) if config.TOOLS_ENABLED else []
    tools_ready = bool(tools) and crowdstrike.configured()

    def _plain_stream():
        """Phase 1 path: single-shot streamed chat, no tools."""
        convo = history + [{"role": "user", "content": message}]
        yield _sse("status", {"message": f"Loading {model}…"})
        assistant = []
        try:
            for chunk in runtime.generate_stream(model, convo, system_prompt):
                assistant.append(chunk)
                yield _sse("token", {"text": chunk})
        except InferenceError as e:
            yield _sse("error", {"message": str(e)})
            return
        except Exception as e:  # defensive: never leak a raw 500 into the stream
            yield _sse("error", {"message": f"Generation failed: {e}"})
            return
        sessions.append(sid, task, model, "assistant", "".join(assistant).strip())
        yield _sse("done", {})

    def _agent_stream():
        """Phase 2 path: prompted-JSON tool loop with a visible step trace."""
        yield _sse("status", {"message": f"Loading {model}…"})

        def _generate(messages, sysp, max_new):
            return runtime.generate_text(model, messages, sysp, max_new)

        assistant = []
        for ev in run_agent(
            generate=_generate,
            base_system_prompt=system_prompt,
            tools=tools,
            user_message=message,
            history=history,
            max_steps=config.AGENT_MAX_STEPS,
            timeout_s=config.AGENT_TIMEOUT_SECONDS,
            step_max_new_tokens=config.AGENT_STEP_MAX_NEW_TOKENS,
        ):
            if ev["event"] == "token":
                assistant.append(ev["data"].get("text", ""))
            yield _sse(ev["event"], ev["data"])
        full = "".join(assistant).strip()
        if full:
            sessions.append(sid, task, model, "assistant", full)

    gen = _agent_stream if tools_ready else _plain_stream
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


@router.post("/workbench/clear")
def workbench_clear(request: Request, task: str = Form(...), model: str = Form(...)):
    sessions.clear(_sid(request), task, model)
    return RedirectResponse(url=f"/workbench?task={task}&model={model}", status_code=303)
