import json
import sys
from collections.abc import Iterator
from typing import Any

from eva.config import AppConfig, get_api_key
from eva.indexing.tokenizer import trim_context
from eva.providers import (
    AuthError,
    Provider,
    RateLimitError,
    ServerError,
    TextDelta,
    ToolCall,
    ToolSpec,
    get_effective_context_tokens,
    register_provider,
)


def __getattr__(name: str) -> Any:
    if name == "genai":
        from google import genai

        globals()["genai"] = genai
        return genai
    if name == "errors":
        from google.genai import errors

        globals()["errors"] = errors
        return errors
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class GeminiProvider(Provider):
    name = "gemini"
    max_rpm = 15
    max_rpd = 1500
    max_context_tokens = 1000000
    default_model: str = "gemini-3-flash"
    supports_tools: bool = True

    def generate_stream(self, system_prompt: str, user_prompt: str, context: str, config: AppConfig) -> Iterator[str]:
        api_key = get_api_key(self.name)
        if not api_key:
            raise AuthError(f"Missing API key for {self.name}. Use: eva config set-key {self.name}")

        _mod = sys.modules[__name__]
        genai = _mod.genai
        errors = _mod.errors

        client = genai.Client(api_key=api_key)

        provider_config = config.providers.get(self.name)
        model = provider_config.model if provider_config else "gemini-3-flash"

        max_tokens = get_effective_context_tokens(self.name, config)
        trimmed_context = trim_context(context, max_tokens=max_tokens) if context else ""

        prompt = ""
        if trimmed_context:
            prompt += f"Context:\n{trimmed_context}\n\n"
        prompt += user_prompt

        try:
            response = client.models.generate_content_stream(
                model=model,
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                ),
            )
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except errors.APIError as e:
            if e.code == 401 or e.code == 403:
                raise AuthError("Invalid API key for Gemini.")
            if e.code == 429:
                raise RateLimitError("Rate limited by Gemini.")
            if e.code in [502, 503]:
                raise ServerError("Gemini server error.")
            raise

    def generate_with_tools(
        self, messages: list[dict], tools: list[ToolSpec], config: AppConfig
    ) -> Iterator[TextDelta | ToolCall]:
        api_key = get_api_key(self.name)
        if not api_key:
            raise AuthError(f"Missing API key for {self.name}. Use: eva config set-key {self.name}")

        _mod = sys.modules[__name__]
        genai = _mod.genai
        errors = _mod.errors

        client = genai.Client(api_key=api_key)

        provider_config = config.providers.get(self.name)
        model = provider_config.model if provider_config else "gemini-3-flash"

        system_instruction, contents = format_gemini_contents(messages)

        gemini_tools = []
        if tools:
            func_decls = []
            for tool in tools:
                func_decls.append(
                    genai.types.FunctionDeclaration(
                        name=tool.name,
                        description=tool.description,
                        parameters=tool.parameters,
                    )
                )
            gemini_tools.append(genai.types.Tool(function_declarations=func_decls))

        genai_config = genai.types.GenerateContentConfig(
            system_instruction=system_instruction if system_instruction else None,
            tools=gemini_tools if gemini_tools else None,
        )

        try:
            response = client.models.generate_content_stream(
                model=model,
                contents=contents,
                config=genai_config,
            )
            for chunk in response:
                fn_calls = getattr(chunk, "function_calls", None)
                if fn_calls:
                    for fn in fn_calls:
                        call_id = getattr(fn, "id", None) or f"call_{getattr(fn, 'name', 'tool')}"
                        raw_args = getattr(fn, "args", {}) or {}
                        args = dict(raw_args) if isinstance(raw_args, dict) else {}
                        yield ToolCall(call_id=str(call_id), name=getattr(fn, "name", ""), arguments=args)

                if hasattr(chunk, "text") and chunk.text:
                    yield TextDelta(content=chunk.text)
        except errors.APIError as e:
            if e.code == 401 or e.code == 403:
                raise AuthError("Invalid API key for Gemini.")
            if e.code == 429:
                raise RateLimitError("Rate limited by Gemini.")
            if e.code in [502, 503]:
                raise ServerError("Gemini server error.")
            raise


def get_models() -> list[dict]:
    api_key = get_api_key("gemini")
    if not api_key:
        return []

    _mod = sys.modules[__name__]
    genai = _mod.genai
    errors = _mod.errors

    try:
        client = genai.Client(api_key=api_key)
        models = []
        for model in client.models.list():
            name = getattr(model, "name", "")
            display_name = getattr(model, "display_name", name)
            if name:
                models.append({"id": name, "name": display_name})
        return models
    except (errors.APIError, AttributeError, KeyError, ValueError, RuntimeError):
        return []


def format_gemini_contents(messages: list[Any]) -> tuple[str, list[Any]]:
    """Convert conversation messages into Gemini-compatible Content objects.

    Supports:
    - System messages extracted into system_instruction string.
    - Model/assistant messages containing tool calls (OpenAI dict style, raw dict style,
      or ToolCall objects) converted to Part(function_call=FunctionCall(...)).
    - Text parts preserved alongside function call parts in model/assistant messages.
    - Tool response messages (role=='tool' or raw dict with response/content) converted to
      Part(function_response=FunctionResponse(...)) under role 'user'.
    - Strict validation: role=='tool' missing or malformed tool_call_id raises ValueError.
    """
    _mod = sys.modules[__name__]
    genai = _mod.genai

    system_instruction = ""
    contents: list[Any] = []
    call_id_to_name: dict[str, str] = {}

    for msg in messages:
        if isinstance(msg, ToolCall):
            fc = genai.types.FunctionCall(name=msg.name, args=dict(msg.arguments or {}), id=msg.call_id)
            if msg.call_id:
                call_id_to_name[str(msg.call_id)] = msg.name
            contents.append(genai.types.Content(role="model", parts=[genai.types.Part(function_call=fc)]))
            continue

        role = msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", None)

        if role == "system":
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
            system_instruction = str(content) if content else ""
            continue

        if isinstance(msg, dict) and "args" in msg and "name" in msg and role not in ("user", "tool"):
            raw_args = msg["args"]
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except (json.JSONDecodeError, TypeError, ValueError):
                    args = {"input": raw_args}
            elif isinstance(raw_args, dict):
                args = dict(raw_args)
            else:
                args = {}
            cid = msg.get("id") or msg.get("call_id")
            if cid:
                call_id_to_name[str(cid)] = msg["name"]
            fc = genai.types.FunctionCall(name=msg["name"], args=args, id=str(cid) if cid else None)
            contents.append(genai.types.Content(role="model", parts=[genai.types.Part(function_call=fc)]))
            continue

        if role in ("tool", "function") or (
            isinstance(msg, dict) and "response" in msg and ("name" in msg or "tool_call_id" in msg)
        ):
            cid = (
                msg.get("tool_call_id") or msg.get("id")
                if isinstance(msg, dict)
                else getattr(msg, "tool_call_id", None)
            )
            if role == "tool" and (not cid or not str(cid).strip()):
                raise ValueError(f"Tool response message missing required 'tool_call_id': {msg}")

            name = msg.get("name") if isinstance(msg, dict) else getattr(msg, "name", None)
            if not name and cid:
                name = call_id_to_name.get(str(cid))
            if not name and cid:
                name = str(cid)
            if not name:
                raise ValueError(f"Tool response message missing tool name: {msg}")

            raw_resp = (
                msg.get("response")
                if isinstance(msg, dict) and "response" in msg
                else (msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None))
            )

            if isinstance(raw_resp, dict):
                resp_dict = dict(raw_resp)
            elif isinstance(raw_resp, str):
                try:
                    parsed = json.loads(raw_resp)
                    resp_dict = parsed if isinstance(parsed, dict) else {"response": raw_resp}
                except (json.JSONDecodeError, TypeError, ValueError):
                    resp_dict = {"response": raw_resp}
            elif raw_resp is None:
                resp_dict = {}
            else:
                resp_dict = {"response": str(raw_resp)}

            fr = genai.types.FunctionResponse(name=name, response=resp_dict, id=str(cid) if cid else None)
            contents.append(genai.types.Content(role="user", parts=[genai.types.Part(function_response=fr)]))
            continue

        if role in ("assistant", "model"):
            parts: list[Any] = []
            content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            if content:
                parts.append(genai.types.Part.from_text(text=str(content)))

            tool_calls = msg.get("tool_calls") if isinstance(msg, dict) else getattr(msg, "tool_calls", None)
            if not tool_calls and isinstance(msg, dict) and "function_call" in msg:
                tool_calls = [msg["function_call"]]

            if tool_calls:
                for tc in tool_calls:
                    if isinstance(tc, ToolCall):
                        tc_id = tc.call_id
                        tc_name = tc.name
                        tc_args = tc.arguments
                    elif isinstance(tc, dict):
                        if "function" in tc and isinstance(tc["function"], dict):
                            tc_id = tc.get("id")
                            tc_name = tc["function"].get("name", "")
                            tc_args = tc["function"].get("arguments", {})
                        else:
                            tc_id = tc.get("id") or tc.get("call_id")
                            tc_name = tc.get("name", "")
                            tc_args = tc.get("args") if "args" in tc else tc.get("arguments", {})
                    else:
                        continue

                    if isinstance(tc_args, str):
                        if not tc_args.strip():
                            tc_args = {}
                        else:
                            try:
                                tc_args = json.loads(tc_args)
                            except (json.JSONDecodeError, TypeError, ValueError):
                                tc_args = {"input": tc_args}
                    if not isinstance(tc_args, dict):
                        tc_args = {}

                    if tc_id:
                        call_id_to_name[str(tc_id)] = tc_name

                    fc = genai.types.FunctionCall(
                        name=tc_name,
                        args=tc_args,
                        id=str(tc_id) if tc_id else None,
                    )
                    parts.append(genai.types.Part(function_call=fc))

            if not parts:
                parts.append(genai.types.Part.from_text(text=""))
            contents.append(genai.types.Content(role="model", parts=parts))
            continue

        content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        contents.append(
            genai.types.Content(
                role="user",
                parts=[genai.types.Part.from_text(text=str(content) if content is not None else "")],
            )
        )

    if not contents:
        contents = [genai.types.Content(role="user", parts=[genai.types.Part.from_text(text="")])]

    return system_instruction, contents


register_provider(GeminiProvider())
