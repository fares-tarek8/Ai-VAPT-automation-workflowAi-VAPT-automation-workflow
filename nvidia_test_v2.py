
import os
from openai import OpenAI

API_KEY = os.getenv("NVIDIA_API_KEY")

if not API_KEY:
    raise SystemExit(
        "ERROR: NVIDIA_API_KEY is not set.\n"
        'Run: export NVIDIA_API_KEY="YOUR_API_KEY"'
    )

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=API_KEY,
    timeout=90.0,
)

MODEL = "nvidia/nemotron-3.5-super-vl-120b-a12b"

print(f"Testing NVIDIA NIM model: {MODEL}")
print("Sending request...\n")

try:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": "Reply with exactly: NVIDIA NIM connection successful."
            }
        ],
        max_tokens=100,
    )

    print("Request completed.")
    print("Model:", response.model)
    print("Finish reason:", response.choices[0].finish_reason)

    message = response.choices[0].message
    print("\nMessage content:")
    print(repr(message.content))

    if message.content:
        print("\nSUCCESS: The model returned text.")
    else:
        print(
            "\nThe API returned a response, but the text content is empty. "
            "Check the full response below."
        )
        print(response.model_dump_json(indent=2))

except Exception as error:
    print("\nAPI REQUEST FAILED")
    print("Error type:", type(error).__name__)
    print("Error details:", str(error))
