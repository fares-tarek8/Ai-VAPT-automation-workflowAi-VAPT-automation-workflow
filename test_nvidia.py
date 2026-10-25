
import os
from openai import OpenAI

api_key = os.getenv("NVIDIA_API_KEY")

if not api_key:
    raise SystemExit(
        "API key missing. Set NVIDIA_API_KEY first."
    )

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=api_key,
    timeout=60.0,
)

try:
    response = client.chat.completions.create(
        model="nvidia/nemotron-3.5-super-vl-120b-a12b",
        messages=[
            {
                "role": "user",
                "content": (
                    "Reply with 'NVIDIA NIM connection successful' "
                    "and briefly explain what an AI penetration "
                    "testing agent does."
                ),
            }
        ],
        max_tokens=150,
    )

    print("\nModel response:")
    print(response.choices[0].message.content)

except Exception as error:
    print(f"\nAPI request failed: {error}")
