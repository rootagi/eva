from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from eva.agent.tools import ToolResult, list_directory, read_file, search_code
from eva.config import AppConfig
from eva.indexing.tokenizer import count_tokens
from eva.providers import Provider, TextDelta, ToolCall, ToolSpec, get_provider
from eva.providers.retry import RetryingStream
from eva.workflows.budget import check_and_increment


class StoppedReason(str, Enum):
    COMPLETED = "completed"
    MAX_TURNS = "max_turns"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REPEATED_CALL_DETECTED = "repeated_call_detected"
    TOKEN_BUDGET_EXHAUSTED = "token_budget_exhausted"


@dataclass
class InvestigationResult:
    final_answer: str | None
    files_read: list[str] = field(default_factory=list)
    turns_used: int = 0
    tokens_used: int = 0
    stopped_reason: StoppedReason = StoppedReason.COMPLETED


INVESTIGATION_SYSTEM_PROMPT = """You are Eva's codebase investigation agent.
You have access to the following read-only tools to explore the user's repository:
1. list_directory(path="."): Lists entries in a directory.
2. read_file(path="..."): Reads the text content of a file.
3. search_code(pattern="...", path="."): Searches code files for a string or regex pattern.

Instructions:
- Use the tools to inspect relevant files before answering.
- Perform targeted file reads based on what you find.
- When you have gathered enough information, provide a thorough, clear answer to the user's question.
"""

EXPLORATION_TOOLS = [
    ToolSpec(
        name="list_directory",
        description="List files and directories in the target repository at path.",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative directory path (defaults to '.')",
                }
            },
        },
    ),
    ToolSpec(
        name="read_file",
        description="Read text content of a file in the repository.",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to file",
                },
                "start_line": {
                    "type": "integer",
                    "description": "1-based starting line number to read from",
                },
                "end_line": {
                    "type": "integer",
                    "description": "1-based ending line number to read to",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum number of bytes to read (default 100000)",
                },
            },
            "required": ["path"],
        },
    ),
    ToolSpec(
        name="search_code",
        description="Search code for a regex pattern or text string across files.",
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Pattern or text to search for",
                },
                "path": {
                    "type": "string",
                    "description": "Subdirectory or file to search in (defaults to '.')",
                },
            },
            "required": ["pattern"],
        },
    ),
]

WEB_TOOLS = [
    ToolSpec(
        name="web_search",
        description="Search the web using SearXNG for documentation, error messages, or security advisories.",
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string",
                },
                "category": {
                    "type": "string",
                    "description": "Category: general, it, science",
                },
            },
            "required": ["query"],
        },
    ),
    ToolSpec(
        name="fetch_url",
        description="Fetch external web page content as Markdown with SSRF protection.",
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "HTTP or HTTPS URL to fetch",
                },
            },
            "required": ["url"],
        },
    ),
]


def _execute_tool_call(
    call: ToolCall, root: Path, force_include: set[str] = frozenset()
) -> tuple[str, bool, str | None]:
    name = call.name
    args = call.arguments or {}

    if name == "list_directory":
        path_arg = args.get("path", ".")
        entries = list_directory(root, path=path_arg, force_include=force_include)
        return json.dumps(entries, indent=2), False, None

    elif name == "read_file":
        path_arg = args.get("path", "")
        start_line = args.get("start_line")
        end_line = args.get("end_line")
        max_bytes = args.get("max_bytes", 100000)
        res: ToolResult = read_file(
            root,
            path=path_arg,
            start_line=start_line,
            end_line=end_line,
            max_bytes=max_bytes,
            force_include=force_include,
        )
        if res.success:
            return res.content or "", True, path_arg
        else:
            return f"Error reading file: {res.error}", False, None

    elif name == "search_code":
        pattern = args.get("pattern", "")
        path_arg = args.get("path", ".")
        hits = search_code(root, pattern=pattern, path=path_arg, force_include=force_include)
        return json.dumps(hits, indent=2), False, None

    elif name == "web_search":
        from eva.agent.tools import web_search

        query_arg = args.get("query", "")
        category_arg = args.get("category", "general")
        res = web_search(query_arg, category=category_arg)
        return str(res.content or res.error or "No results"), False, None

    elif name == "fetch_url":
        from eva.agent.tools import fetch_url

        url_arg = args.get("url", "")
        res = fetch_url(url_arg)
        return str(res.content or res.error or "No content"), False, None

    else:
        return f"Unknown tool: {name}", False, None


def run_investigation(
    query: str,
    root: Path,
    config: AppConfig,
    provider_name: str,
    max_turns: int = 8,
    max_tokens_budget: int | None = None,
    on_stream_text: Callable[[str], None] | None = None,
    on_tool_start: Callable[[str, dict], None] | None = None,
    provider_override: Provider | None = None,
    force_include: set[str] = frozenset(),
    web_enabled: bool = False,
    max_web_calls: int = 5,
) -> InvestigationResult:
    """Run an agentic multi-turn repository investigation loop."""
    provider = provider_override or get_provider(provider_name)
    if provider is None:
        return InvestigationResult(
            final_answer=None,
            stopped_reason=StoppedReason.COMPLETED,
            tokens_used=0,
        )

    files_read_set: set[str] = set()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": INVESTIGATION_SYSTEM_PROMPT},
        {"role": "user", "content": query},
    ]

    last_turn_signatures: list[tuple[str, str]] = []
    accumulated_answer: str = ""
    cumulative_tokens: int = 0
    web_calls: int = 0

    active_tools = list(EXPLORATION_TOOLS)
    if web_enabled:
        active_tools.extend(WEB_TOOLS)

    for turn in range(1, max_turns + 1):
        allowed = check_and_increment(
            provider=provider_name,
            max_rpm=getattr(provider, "max_rpm", 60),
            max_rpd=getattr(provider, "max_rpd", 1000),
        )
        if not allowed:
            partial_note = "\n\n[Note: Investigation ended early because provider API rate/quota budget was exhausted.]"
            final_ans = accumulated_answer + partial_note if accumulated_answer else partial_note
            return InvestigationResult(
                final_answer=final_ans,
                files_read=sorted(files_read_set),
                turns_used=turn,
                tokens_used=cumulative_tokens,
                stopped_reason=StoppedReason.BUDGET_EXHAUSTED,
            )

        # Count tokens in input messages for this turn
        turn_input_tokens = sum(
            count_tokens(str(m.get("content") or ""))
            + (count_tokens(json.dumps(m.get("tool_calls"))) if m.get("tool_calls") else 0)
            for m in messages
        )
        cumulative_tokens += turn_input_tokens

        if max_tokens_budget is not None and cumulative_tokens >= max_tokens_budget:
            note = f"\n\n[Note: Investigation ended early because cumulative token budget was exceeded ({cumulative_tokens} >= {max_tokens_budget}).]"
            return InvestigationResult(
                final_answer=accumulated_answer + note if accumulated_answer else note,
                files_read=sorted(files_read_set),
                turns_used=turn,
                tokens_used=cumulative_tokens,
                stopped_reason=StoppedReason.TOKEN_BUDGET_EXHAUSTED,
            )

        tool_calls: list[ToolCall] = []
        turn_text_chunks: list[str] = []

        try:
            retrying_events = RetryingStream(provider.generate_with_tools, messages, active_tools, config)
            for event in retrying_events:
                if isinstance(event, TextDelta):
                    turn_text_chunks.append(event.content)
                    if on_stream_text:
                        on_stream_text(event.content)
                elif isinstance(event, ToolCall):
                    tool_calls.append(event)
        except Exception as exc:  # noqa: BLE001
            err_ans = f"Error during investigation: {exc}"
            return InvestigationResult(
                final_answer=err_ans,
                files_read=sorted(files_read_set),
                turns_used=turn,
                tokens_used=cumulative_tokens,
                stopped_reason=StoppedReason.COMPLETED,
            )

        turn_text = "".join(turn_text_chunks)
        if turn_text:
            accumulated_answer += turn_text
            cumulative_tokens += count_tokens(turn_text)

        if tool_calls:
            for tc in tool_calls:
                cumulative_tokens += count_tokens(tc.name) + count_tokens(json.dumps(tc.arguments))

        if max_tokens_budget is not None and cumulative_tokens >= max_tokens_budget:
            note = f"\n\n[Note: Investigation ended early because cumulative token budget was exceeded ({cumulative_tokens} >= {max_tokens_budget}).]"
            return InvestigationResult(
                final_answer=accumulated_answer + note if accumulated_answer else note,
                files_read=sorted(files_read_set),
                turns_used=turn,
                tokens_used=cumulative_tokens,
                stopped_reason=StoppedReason.TOKEN_BUDGET_EXHAUSTED,
            )

        if not tool_calls:
            return InvestigationResult(
                final_answer=accumulated_answer or turn_text,
                files_read=sorted(files_read_set),
                turns_used=turn,
                tokens_used=cumulative_tokens,
                stopped_reason=StoppedReason.COMPLETED,
            )

        current_turn_signatures = [
            (
                tc.name,
                json.dumps(tc.arguments, sort_keys=True) if isinstance(tc.arguments, dict) else str(tc.arguments),
            )
            for tc in tool_calls
        ]
        if current_turn_signatures and current_turn_signatures == last_turn_signatures:
            note = "\n\n[Note: Investigation interrupted due to repeated identical tool execution.]"
            return InvestigationResult(
                final_answer=accumulated_answer + note if accumulated_answer else note,
                files_read=sorted(files_read_set),
                turns_used=turn,
                tokens_used=cumulative_tokens,
                stopped_reason=StoppedReason.REPEATED_CALL_DETECTED,
            )
        last_turn_signatures = current_turn_signatures

        formatted_tool_calls = [
            {
                "id": tc.call_id,
                "type": "function",
                "function": {
                    "name": tc.name,
                    "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else str(tc.arguments),
                },
            }
            for tc in tool_calls
        ]
        messages.append(
            {
                "role": "assistant",
                "content": turn_text if turn_text else None,
                "tool_calls": formatted_tool_calls,
            }
        )

        for tc in tool_calls:
            if on_tool_start:
                on_tool_start(tc.name, tc.arguments)

            if tc.name in ("web_search", "fetch_url"):
                if web_calls >= max_web_calls:
                    res_str = f"Error: Maximum web call limit of {max_web_calls} exceeded."
                    is_read = False
                    path_read = None
                else:
                    web_calls += 1
                    res_str, is_read, path_read = _execute_tool_call(tc, root, force_include=force_include)
            else:
                res_str, is_read, path_read = _execute_tool_call(tc, root, force_include=force_include)

            if is_read and path_read:
                files_read_set.add(path_read)

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.call_id,
                    "name": tc.name,
                    "content": res_str,
                }
            )

    note = f"\n\n[Note: Reached maximum turn limit of {max_turns} turns.]"
    return InvestigationResult(
        final_answer=accumulated_answer + note if accumulated_answer else note,
        files_read=sorted(files_read_set),
        turns_used=max_turns,
        tokens_used=cumulative_tokens,
        stopped_reason=StoppedReason.MAX_TURNS,
    )
