
import time
import requests


GITHUB_DEVICE_URL = "https://github.com/login/device/code"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com/user"


CLIENT_ID = "Iv23licLNO2jpGjrIZqK"


SCOPES = ["read:user", "repo"]


def request_device_code() -> dict:
    """Request a device code from GitHub."""

    response = requests.post(
        GITHUB_DEVICE_URL,
        data={
            "client_id": CLIENT_ID,
            "scope": " ".join(SCOPES),
        },
        headers={
            "Accept": "application/json",
        },
        timeout=10,
    )

    response.raise_for_status()

    return response.json()


def request_access_token(device_code: str) -> dict:
    """Poll GitHub until the user authorizes the application."""

    while True:
        response = requests.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={
                "Accept": "application/json",
            },
            timeout=10,
        )

        response.raise_for_status()
        data = response.json()

        if "access_token" in data:
            return data

        error = data.get("error")

        if error == "authorization_pending":
            time.sleep(data.get("interval", 5))
            continue

        if error == "slow_down":
            time.sleep(data.get("interval", 5) + 5)
            continue

        if error == "expired_token":
            raise RuntimeError("The device code has expired.")

        if error == "access_denied":
            raise RuntimeError("GitHub authorization was denied.")

        raise RuntimeError(
            f"GitHub authentication failed: {error}"
        )


def get_github_user(access_token: str) -> dict:
    """Retrieve the authenticated GitHub user."""

    response = requests.get(
        GITHUB_API_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10,
    )

    response.raise_for_status()

    return response.json()


def login() -> tuple[str, dict]:
    """Authenticate the user with GitHub."""

    device_data = request_device_code()

    print("\nOpen:")
    print(device_data["verification_uri"])

    print("\nEnter this code:")
    print(device_data["user_code"])

    print("\nWaiting for GitHub authorization...")

    token_data = request_access_token(
        device_data["device_code"]
    )

    access_token = token_data["access_token"]

    user = get_github_user(access_token)

    return access_token, user
