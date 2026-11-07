"""Bounded authenticated passive ZAP probe: approved nonproduction /api/me only.

No spider, active scan, Microsoft login replay, business record or write route.
Tokens, raw requests, responses and ZAP logs never become report artifacts.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.workforce.invalid"
HOST = urllib.parse.urlsplit(API).hostname


def alert_counts(alerts):
    counts = Counter()
    for alert in alerts:
        identifier = alert.get("pluginId")
        # The live API uses a risk label; baseline JSON uses a numeric riskcode.
        labels = {"Informational": "0", "Low": "1", "Medium": "2", "High": "3"}
        risk = alert.get("riskcode", labels.get(alert.get("risk")))
        if "risk" in alert and labels.get(alert["risk"]) != risk:
            raise ValueError("Conflicting passive alert risk metadata")
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9]{1,8}", identifier) or risk not in ("0", "1", "2", "3"):
            raise ValueError("Unsupported passive alert metadata")
        counts[(identifier, risk)] += 1
    return [{"ruleId": identifier, "risk": int(risk), "count": count}
            for (identifier, risk), count in sorted(counts.items())]


def image_pin():
    pin = json.loads((ROOT / "security/zap-lock.json").read_text(encoding="utf-8"))["image"]
    if not re.fullmatch(r"ghcr.io/zaproxy/zaproxy@sha256:[a-f0-9]{64}", pin):
        raise ValueError("Invalid pinned ZAP image")
    return pin


def run(token_file, expected_actor, output, docker="docker"):
    if (not token_file.is_absolute() or token_file.is_symlink() or token_file.resolve().is_relative_to(ROOT)
            or not token_file.is_file() or token_file.stat().st_size > 16384):
        raise ValueError("Use a small private token file outside the repository")
    if output.exists():
        raise ValueError("Choose a new safe-summary file")
    if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", expected_actor):
        raise ValueError("Exact approved account object ID required")
    token = token_file.read_text(encoding="utf-8-sig").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{50,16000}", token):
        raise ValueError("Invalid private access token")
    image, key = image_pin(), secrets.token_hex(24)
    container = "workforce-zap-auth-" + secrets.token_hex(6)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def docker_run(*args, timeout=120):
        result = subprocess.run([docker, *args], capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("ZAP container operation failed; private output withheld")
        return result.stdout.decode("utf-8").strip()

    try:
        docker_run("run", "--detach", "--name", container, "--platform", "linux/amd64",
                   "--publish", "127.0.0.1::8080", "--memory", "2g", "--cpus", "2",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   image, "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080",
                   "-config", "api.key=" + key, "-config", "api.addrs.addr.name=.*",
                   "-config", "api.addrs.addr.regex=true", timeout=600)
        mapping = docker_run("port", container, "8080/tcp")
        if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", mapping):
            raise RuntimeError("ZAP must bind to loopback only")

        def call(path, **values):
            data = urllib.parse.urlencode({"apikey": key, **values}).encode()
            request = urllib.request.Request("http://" + mapping + "/JSON/" + path + "/", data=data, headers={"Host": "zap"})
            with opener.open(request, timeout=30) as response:
                return json.load(response)

        for attempt in range(180):
            try:
                call("core/view/version")
                break
            except Exception:
                if attempt == 179:
                    raise RuntimeError("ZAP startup did not complete within three minutes") from None
                time.sleep(1)

        def probe(access_token=None):
            authorization = "Authorization: Bearer " + access_token + "\r\n" if access_token else ""
            request = "GET " + API + "/api/me HTTP/1.1\r\nHost: " + HOST + "\r\n" + authorization + "Connection: close\r\n\r\n"
            message = call("core/action/sendRequest", request=request, followRedirects="false")["sendRequest"][0]
            header = message["responseHeader"]
            status = int(header.split(" ", 2)[1])
            return status, message.get("responseBody", "")

        anonymous, _ = probe()
        if anonymous != 401:
            raise RuntimeError("Anonymous denial was not confirmed; probe stopped")
        authenticated, body = probe(token)
        if authenticated != 200 or json.loads(body).get("objectId", "").lower() != expected_actor:
            raise RuntimeError("Approved authenticated identity was not confirmed; probe stopped")
        for attempt in range(60):
            if call("pscan/view/recordsToScan").get("recordsToScan") == "0":
                break
            if attempt == 59:
                raise RuntimeError("Passive analysis did not complete")
            time.sleep(1)
        alerts = call("core/view/alerts", baseurl=API, start="0", count="1000")["alerts"]
        if len(alerts) >= 1000:
            raise RuntimeError("Passive results exceeded the bounded summary")
        receipt = {"schemaVersion": 1, "mode": "authenticated-passive-read-only", "completed": True,
                   "image": image, "anonymousStatus": anonymous, "authenticatedStatus": authenticated,
                   "identityVerified": True, "requests": 2, "activeScan": False,
                   "businessWrites": 0, "enforced": False, "alerts": alert_counts(alerts)}
    finally:
        # This removes the container's private history/logs, including tokens and /me body.
        cleanup = subprocess.run([docker, "rm", "--force", container], capture_output=True, timeout=30)
        if cleanup.returncode:
            raise RuntimeError("Private ZAP container cleanup could not be confirmed")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--expected-object-id", "--expected-fictional-object-id", dest="expected_actor", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args()
    try:
        run(args.token_file, args.expected_actor, args.output, args.docker)
    except Exception:
        raise SystemExit("Authenticated passive check incomplete. Check Docker, the nonproduction API and fresh approved sign-in. No clean result is claimed; private error details are withheld.")
