"""
Pushes a new token value into the SCAN_TOKEN secret of every repo listed in
repos.json. Makes API calls only, never commits anything.

Env vars (both come from this repo's secrets):
  ADMIN_PAT        token with "Secrets: Read and write" on the target repos
  NEW_SCAN_TOKEN   the new token value to distribute
"""

import base64
import json
import os
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from nacl import encoding, public

API = "https://api.github.com"


def api(method, path, token, body=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = json.dumps(body).encode() if body is not None else None
    req = Request(f"{API}{path}", data=data, headers=headers, method=method)
    with urlopen(req) as resp:
        raw = resp.read().decode()
        return resp.status, (json.loads(raw) if raw else {})


def encrypt(public_key_b64, value):
    key = public.PublicKey(public_key_b64.encode(), encoding.Base64Encoder())
    sealed = public.SealedBox(key).encrypt(value.encode())
    return base64.b64encode(sealed).decode()


def update_secret(owner, repo, name, value, admin_pat):
    _, key_data = api("GET", f"/repos/{owner}/{repo}/actions/secrets/public-key", admin_pat)
    payload = {
        "encrypted_value": encrypt(key_data["key"], value),
        "key_id": key_data["key_id"],
    }
    status, _ = api("PUT", f"/repos/{owner}/{repo}/actions/secrets/{name}", admin_pat, payload)
    return status  # 201 = created, 204 = updated


def main():
    admin_pat = (os.environ.get("ADMIN_PAT") or "").strip()
    new_token = (os.environ.get("NEW_SCAN_TOKEN") or "").strip()

    if not admin_pat or not new_token:
        print("ERROR: ADMIN_PAT and NEW_SCAN_TOKEN must both be set as secrets in this repo.")
        sys.exit(1)

    with open("repos.json") as f:
        config = json.load(f)

    owner = config["owner"]
    secret_name = config["secret_name"]
    ok, failed = [], []

    for repo in config["repos"]:
        try:
            status = update_secret(owner, repo, secret_name, new_token, admin_pat)
            ok.append(repo)
            print(f"[ok]     {repo} (HTTP {status})")
        except HTTPError as e:
            failed.append(repo)
            hint = {
                401: "ADMIN_PAT is expired or invalid",
                403: "ADMIN_PAT lacks 'Secrets: Read and write' on this repo",
                404: "repo name wrong, or ADMIN_PAT can't see this repo",
            }.get(e.code, "unexpected error")
            print(f"[FAILED] {repo} (HTTP {e.code}: {hint})")
        except Exception as e:
            failed.append(repo)
            print(f"[FAILED] {repo} ({type(e).__name__})")

    print(f"\nUpdated: {len(ok)}  Failed: {len(failed)}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
