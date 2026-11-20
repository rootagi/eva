from typing import Any

from eva.plugins.loader import clear_workflow_hooks, get_workflow_hooks, register_workflow_hook
from eva.plugins.protocol import WorkflowHooks
from eva.workflows.engine import Step, Workflow, run_workflow


class LifecycleTrackerHook(WorkflowHooks):
    def __init__(self):
        self.events = []

    def on_workflow_start(self, workflow_name: str) -> None:
        self.events.append(("workflow_start", workflow_name))

    def on_step_start(self, step_name: str) -> None:
        self.events.append(("step_start", step_name))

    def on_step_complete(self, step_name: str, step_output: Any) -> None:
        self.events.append(("step_complete", step_name, step_output))

    def on_step_error(self, step_name: str, error_message: str) -> None:
        self.events.append(("step_error", step_name, error_message))

    def on_workflow_complete(self, workflow_name: str, summary: Any) -> None:
        self.events.append(("workflow_complete", workflow_name, summary))


class CrashingHook(WorkflowHooks):
    def on_workflow_start(self, workflow_name: str) -> None:
        raise RuntimeError("Explosion on start")

    def on_step_start(self, step_name: str) -> None:
        raise RuntimeError("Explosion on step start")

    def on_step_complete(self, step_name: str, step_output: Any) -> None:
        raise RuntimeError("Explosion on step complete")

    def on_step_error(self, step_name: str, error_message: str) -> None:
        raise RuntimeError("Explosion on step error")

    def on_workflow_complete(self, workflow_name: str, summary: Any) -> None:
        raise RuntimeError("Explosion on workflow complete")


def test_workflow_hooks_registry():
    clear_workflow_hooks()
    assert len(get_workflow_hooks()) == 0

    hook = LifecycleTrackerHook()
    register_workflow_hook(hook)
    assert hook in get_workflow_hooks()

    clear_workflow_hooks()
    assert len(get_workflow_hooks()) == 0


def test_workflow_hooks_lifecycle_dispatch():
    clear_workflow_hooks()
    hook = LifecycleTrackerHook()
    register_workflow_hook(hook)

    wf = Workflow(
        name="test-lifecycle-wf",
        description="Lifecycle test",
        steps=[
            Step(name="step-1", command="echo hello", description="First step"),
            Step(name="step-2", command="echo world", description="Second step"),
        ],
    )

    try:
        results = run_workflow(wf, interactive=False)
        assert len(results) == 2
        assert results[0]["status"] == "success"
        assert results[1]["status"] == "success"

        event_names = [e[0] for e in hook.events]
        assert event_names == [
            "workflow_start",
            "step_start",
            "step_complete",
            "step_start",
            "step_complete",
            "workflow_complete",
        ]
        assert hook.events[0] == ("workflow_start", "test-lifecycle-wf")
        assert hook.events[-1][0] == "workflow_complete"
        assert hook.events[-1][1] == "test-lifecycle-wf"
        summary = hook.events[-1][2]
        assert isinstance(summary, dict)
        assert summary.get("status") == "success"
    finally:
        clear_workflow_hooks()


def test_workflow_hooks_error_isolation():
    """Hook exceptions must not disrupt workflow execution."""
    clear_workflow_hooks()
    crashing_hook = CrashingHook()
    register_workflow_hook(crashing_hook)

    wf = Workflow(
        name="test-isolated-wf",
        description="Isolation test",
        steps=[
            Step(name="step-ok", command="echo resilience", description="Step"),
        ],
    )

    try:
        results = run_workflow(wf, interactive=False)
        assert len(results) == 1
        assert results[0]["status"] == "success"
    finally:
        clear_workflow_hooks()


def test_workflow_hooks_output_secret_redaction():
    """Step outputs passed to on_step_complete must be redacted."""
    clear_workflow_hooks()
    tracker = LifecycleTrackerHook()
    register_workflow_hook(tracker)

    wf = Workflow(
        name="test-redact-wf",
        description="Redaction test",
        steps=[
            Step(
                name="step-secret",
                command="echo 'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
                description="Output secret",
            ),
        ],
    )

    try:
        results = run_workflow(wf, interactive=False)
        assert len(results) == 1

        complete_events = [e for e in tracker.events if e[0] == "step_complete"]
        assert len(complete_events) == 1
        output = complete_events[0][2]
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(output)
        assert "[REDACTED" in str(output)
    finally:
        clear_workflow_hooks()
