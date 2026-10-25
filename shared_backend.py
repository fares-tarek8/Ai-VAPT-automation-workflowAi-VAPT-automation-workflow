
import os
import hmac
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from openai import OpenAI

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
TEAM_API_KEY = os.getenv("TEAM_API_KEY")

if not NVIDIA_API_KEY or not TEAM_API_KEY:
    raise RuntimeError(
        "Set both NVIDIA_API_KEY and TEAM_API_KEY before starting."
    )

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=NVIDIA_API_KEY,
    timeout=90.0,
)

MODEL = "nvidia/nemotron-3.5-super-vl-120b-a12b"
app = FastAPI(title="Team AI Model API")


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


@app.get("/")
def home():
    return {"status": "online", "service": "Team AI Model API"}


@app.post("/chat")
def chat(
    request: ChatRequest,
    x_team_key: str = Header(default=""),
):
    if not hmac.compare_digest(x_team_key, TEAM_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid team key")

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": request.message}],
            max_tokens=500,
        )
        answer = response.choices[0].message.content

        return {
            "model": response.model,
            "answer": answer or "",
        }
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="The model provider request failed."
        )
