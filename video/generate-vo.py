"""Generate voiceover using Gemini TTS (v1beta1 API)."""
import json
import base64
import subprocess
from pathlib import Path

import httpx

PROJECT = "yuhina-496113"
API = "https://texttospeech.googleapis.com/v1beta1/text:synthesize"
VOICE = "Fenrir"
MODEL = "gemini-3.1-flash-tts-preview"

SEGMENTS = [
    {
        "id": "s1", "start": 0.0,
        "text": "Introducing Pangolin. Built for the Sola Security Hackathon.",
    },
    {
        "id": "s2", "start": 5.0,
        "text": "Sola's pipeline scans your GitHub workflows daily, classifying findings and alerting your team.",
    },
    {
        "id": "s3", "start": 11.0,
        "text": "Our CLI pulls data from Sola MCP. The regex engine scans one hundred five workflows in a tenth of a second. Then GPT five point five goes deep, reasoning through attack chains. Six confirmed, zero false positives, twenty-nine proof of concept files.",
    },
    {
        "id": "s4", "start": 28.0,
        "text": "The report shows severity breakdown, attack scenarios, and downloadable proof of concept files.",
    },
    {
        "id": "s5", "start": 38.0,
        "text": "Detection isn't enough. One command generates a fix and opens a GitHub pull request with full vulnerability context.",
    },
    {
        "id": "s6", "start": 50.0,
        "text": "Everything flows to Slack. Alerts, reports, fix notifications. A complete security loop.",
    },
    {
        "id": "s7", "start": 56.5,
        "text": "Pangolin. Scan. Analyze. Fix. Automatically.",
    },
]

PROMPT = "Speak in a clear, confident, professional tone. Like a tech demo narrator presenting a product. Moderate pace, clean enunciation."


def get_token():
    return subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True,
    ).stdout.strip()


def synthesize(text: str, output_path: str):
    token = get_token()
    body = {
        "input": {
            "text": text,
            "prompt": PROMPT,
        },
        "voice": {
            "languageCode": "en-US",
            "name": VOICE,
            "modelName": MODEL,
        },
        "audioConfig": {
            "audioEncoding": "LINEAR16",
            "sampleRateHertz": 24000,
            "speakingRate": 1.15,
        },
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "x-goog-user-project": PROJECT,
        "Content-Type": "application/json",
    }
    resp = httpx.post(API, json=body, headers=headers, timeout=30)
    resp.raise_for_status()
    audio_b64 = resp.json()["audioContent"]
    Path(output_path).write_bytes(base64.b64decode(audio_b64))
    size = Path(output_path).stat().st_size
    dur = size / (24000 * 2)
    print(f"  {Path(output_path).name} ({dur:.1f}s)")


def main():
    out_dir = Path("vo_segments")
    out_dir.mkdir(exist_ok=True)

    for seg in SEGMENTS:
        wav_path = out_dir / f"{seg['id']}.wav"
        print(f"Generating {seg['id']}...")
        synthesize(seg["text"], str(wav_path))

    # Mix segments at their start times
    inputs = []
    filter_parts = []
    for i, seg in enumerate(SEGMENTS):
        inputs.extend(["-i", str(out_dir / f"{seg['id']}.wav")])
        delay_ms = int(seg["start"] * 1000)
        filter_parts.append(f"[{i}]adelay={delay_ms}|{delay_ms}[d{i}]")

    mix_inputs = "".join(f"[d{i}]" for i in range(len(SEGMENTS)))
    filter_parts.append(f"{mix_inputs}amix=inputs={len(SEGMENTS)}:duration=longest:normalize=0[out]")

    cmd = ["ffmpeg", "-y", *inputs, "-filter_complex", ";".join(filter_parts), "-map", "[out]", "-ar", "24000", "-ac", "1", "voiceover-mixed.wav"]
    print("\nMixing...")
    subprocess.run(cmd, capture_output=True)

    # Pad to 60 seconds
    subprocess.run(["ffmpeg", "-y", "-i", "voiceover-mixed.wav", "-af", "apad=whole_dur=60", "-ar", "24000", "-ac", "1", "voiceover-60s.wav"], capture_output=True)
    print("Done: voiceover-60s.wav")


if __name__ == "__main__":
    main()
