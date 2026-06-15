"""Generate voiceover — sequential concat, no overlap."""
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
    {"id": "s1", "text": "Introducing Pangolin. Built for the Sola Security Hackathon.", "gap_after": 0.8},
    {"id": "s2", "text": "Sola scans your workflows daily, classifying findings and alerting your team.", "gap_after": 0.8},
    {"id": "s3", "text": "Our CLI pulls data from Sola MCP. Regex scans one hundred five workflows in a tenth of a second. GPT five point five reasons through attack chains. Six confirmed, zero false positives. Semgrep cross-validates all seventeen patterns.", "gap_after": 0.8},
    {"id": "s4", "text": "The report shows severity, attack scenarios, and downloadable proof of concept files.", "gap_after": 1.0},
    {"id": "s5", "text": "One command generates a fix and opens a GitHub pull request with full context.", "gap_after": 1.0},
    {"id": "s6", "text": "Everything flows to Slack. A complete security loop.", "gap_after": 0.8},
    {"id": "s7", "text": "Pangolin. Scan. Analyze. Fix. Automatically.", "gap_after": 0.5},
]

PROMPT = "Speak in a clear, confident, professional tone. Like a tech demo narrator presenting a product. Moderate pace, clean enunciation."


def get_token():
    return subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True,
    ).stdout.strip()


def synthesize(text, output_path):
    token = get_token()
    body = {
        "input": {"text": text, "prompt": PROMPT},
        "voice": {"languageCode": "en-US", "name": VOICE, "modelName": MODEL},
        "audioConfig": {"audioEncoding": "LINEAR16", "sampleRateHertz": 24000, "speakingRate": 1.15},
    }
    resp = httpx.post(API, json=body, headers={
        "Authorization": f"Bearer {token}",
        "x-goog-user-project": PROJECT,
        "Content-Type": "application/json",
    }, timeout=30)
    resp.raise_for_status()
    Path(output_path).write_bytes(base64.b64decode(resp.json()["audioContent"]))


def get_duration(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
                       capture_output=True, text=True)
    return float(r.stdout.strip())


def main():
    out_dir = Path("vo_segments")
    out_dir.mkdir(exist_ok=True)

    # Generate each segment
    for seg in SEGMENTS:
        wav = out_dir / f"{seg['id']}.wav"
        print(f"Generating {seg['id']}...")
        synthesize(seg["text"], str(wav))
        dur = get_duration(str(wav))
        seg["duration"] = dur
        print(f"  {dur:.1f}s")

    # Calculate sequential start times
    t = 0.0
    for seg in SEGMENTS:
        seg["start"] = round(t, 2)
        t += seg["duration"] + seg["gap_after"]

    total = round(t, 2)
    print(f"\nTimeline ({total:.1f}s total):")
    for seg in SEGMENTS:
        end = round(seg["start"] + seg["duration"], 1)
        print(f"  {seg['id']}: {seg['start']:.1f}s - {end}s (dur {seg['duration']:.1f}s)")

    # Concat with silence gaps using ffmpeg
    # Build filter: each segment delayed, then amix
    inputs = []
    filter_parts = []
    for i, seg in enumerate(SEGMENTS):
        inputs.extend(["-i", str(out_dir / f"{seg['id']}.wav")])
        delay_ms = int(seg["start"] * 1000)
        filter_parts.append(f"[{i}]adelay={delay_ms}|{delay_ms}[d{i}]")

    mix_inputs = "".join(f"[d{i}]" for i in range(len(SEGMENTS)))
    filter_parts.append(f"{mix_inputs}amix=inputs={len(SEGMENTS)}:duration=longest:normalize=0[out]")

    cmd = ["ffmpeg", "-y", *inputs, "-filter_complex", ";".join(filter_parts),
           "-map", "[out]", "-ar", "24000", "-ac", "1", "voiceover-60s.wav"]
    subprocess.run(cmd, capture_output=True)

    actual_dur = get_duration("voiceover-60s.wav")
    print(f"\nFinal audio: {actual_dur:.1f}s")

    # Save timeline for HTML sync
    timeline = [{"id": s["id"], "start": s["start"], "duration": s["duration"],
                 "end": round(s["start"] + s["duration"], 2), "text": s["text"]}
                for s in SEGMENTS]
    with open("timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)
    print("Saved timeline.json — use these times for HTML scenes + subtitles")


if __name__ == "__main__":
    main()
