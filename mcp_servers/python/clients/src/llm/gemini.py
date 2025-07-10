import requests
import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict

@dataclass
class ChatMessage:
    role: str
    content: str

@dataclass
class SuccessResponseDataFormat:
    total_llm_calls: int
    total_tokens: int
    total_input_tokens: int
    total_output_tokens: int
    final_llm_response: Dict[str, Any]
    llm_responses_arr: List[Dict[str, Any]]
    messages: List[str]
    output_type: str

@dataclass
class LlmResponseStruct:
    Data: Optional[Dict[str, Any]]
    Error: Optional[Union[Exception, str, Dict[str, Any]]]
    Status: bool

@dataclass
class GeminiChatCompletionParams:
    input: str = ''
    images_arr: List[Any] = field(default_factory=list)
    input_type: str = 'text'
    is_stream: bool = False
    prompt: str = ''
    api_key: str = ''
    chat_model: str = 'gemini-2.0-pro'
    vision_model: str = 'gemini-pro-vision'
    speech_model: str = ''
    chat_history: List[ChatMessage] = field(default_factory=list)
    tools: List[Dict[str, Any]] = field(default_factory=list)
    temperature: float = 0.1
    max_tokens: int = 1000
    forced_tool_calls: Optional[Any] = None
    tool_choice: str = 'auto'

async def gemini_processor(data: Dict[str, Any]) -> LlmResponseStruct:
    """Gemini LLM Processor"""
    try:
        # Parse parameters
        params = GeminiChatCompletionParams(
            input=data.get('input', ''),
            images_arr=data.get('images_arr', []),
            input_type=data.get('input_type', 'text'),
            is_stream=data.get('is_stream', False),
            prompt=data.get('prompt', ''),
            api_key=data.get('api_key', ''),
            chat_model=data.get('chat_model', 'gemini-2.0-pro'),
            vision_model=data.get('vision_model', 'gemini-pro-vision'),
            speech_model=data.get('speech_model', ''),
            chat_history=[ChatMessage(**msg) if isinstance(msg, dict) else msg
                          for msg in data.get('chat_history', [])],
            tools=data.get('tools', []),
            temperature=data.get('temperature', 0.1),
            max_tokens=data.get('max_tokens', 1000),
            forced_tool_calls=data.get('forced_tool_calls'),
            tool_choice=data.get('tool_choice', 'auto')
        )

        # Model selection
        selected_model = params.chat_model
        if params.input_type == 'image':
            selected_model = params.vision_model

        # Validate required fields
        if not params.api_key:
            return LlmResponseStruct(Data=None, Error="Gemini API Key is required", Status=False)

        if not params.prompt and not params.input:
            return LlmResponseStruct(Data=None, Error="Prompt or input is required", Status=False)

        # Build chat contents
        chat_contents = []
        for msg in params.chat_history:
            if msg.role in ['user', 'model']:
                chat_contents.append({
                    "role": msg.role,
                    "parts": [{"text": msg.content}]
                })

        chat_contents.append({
            "role": "user",
            "parts": [{"text": params.input}]
        })

        # Build payload
        payload = {
            "system_instruction": {
                "parts": [{"text": params.prompt}]
            },
            "contents": chat_contents,
            "generationConfig": {
                "temperature": params.temperature,
                "maxOutputTokens": params.max_tokens
            }
        }


        if params.tools:
            function_declarations = []
            for tool in params.tools:
                func = tool.get("function", {})
                parameters = func.get("parameters", {})
                props = parameters.get("properties", {})

                processed_props = {}
                for key, val in props.items():
                    if val.get("type") == "array":
                        processed_props[key] = {
                            "type": "array",
                            "items": {"type": val.get("items", {}).get("type", "string")},
                            "default": val.get("default", []),
                            "description": val.get("description", "")
                        }
                    else:
                        processed_props[key] = {
                            "type": val.get("type", "string"),
                            "default": val.get("default", ""),
                            "description": val.get("description", "")
                        }

                function_declarations.append({
                    "name": func.get("name"),
                    "description": func.get("description"),
                    "parameters": {
                        "type": parameters.get("type", "object"),
                        "properties": processed_props,
                        "required": parameters.get("required", [])
                    }
                })

            payload["tools"] = [{"functionDeclarations": function_declarations}]

        # Send request
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{selected_model}:generateContent?key={params.api_key}"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()

        response_data = response.json()

        message_content = response_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        tool_call = response_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("functionCall", None)
        is_tool_call = tool_call is not None

        usage = response_data.get("usageMetadata", {})

        final_format = SuccessResponseDataFormat(
            total_llm_calls=1,
            total_tokens=usage.get("totalTokenCount", 0),
            total_input_tokens=usage.get("promptTokenCount", 0),
            total_output_tokens=usage.get("candidatesTokenCount", 0),
            final_llm_response=response_data,
            llm_responses_arr=[response_data],
            messages=[message_content],
            output_type="tool_call" if is_tool_call else "text"
        )

        return LlmResponseStruct(Data=asdict(final_format), Error=None, Status=True)

    except requests.exceptions.RequestException as req_err:
        err_data = None
        if hasattr(req_err, 'response') and req_err.response is not None:
            try:
                err_data = req_err.response.json()
            except ValueError:
                err_data = req_err.response.text
        else:
            err_data = str(req_err)
        return LlmResponseStruct(Data=None, Error=err_data, Status=False)

    except Exception as err:
        return LlmResponseStruct(Data=None, Error=err, Status=False)
