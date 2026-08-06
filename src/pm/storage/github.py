import base64
import requests
from .base import StorageBackend


class GitHubStorage(StorageBackend):
    """Stores the vault as a file in a GitHub repository.

    Uses the GitHub Contents API. The vault content is stored
    base64-encoded inside a JSON payload (the API convention).
    """

    def __init__(self, access_token: str, owner: str, repo: str, path: str = "vault.enc"):
        self._token = access_token
        self.owner = owner
        self.repo = repo
        self.path = path

    # -- API helpers --------------------------------------------------

    @property
    def _api_url(self) -> str:
        return f"https://api.github.com/repos/{self.owner}/{self.repo}/contents/{self.path}"

    @property
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # -- StorageBackend interface -------------------------------------

    def upload(self, data: bytes) -> None:
        """Create or update the vault file on GitHub."""
        encoded = base64.b64encode(data).decode()

        payload: dict = {
            "message": "Update vault",
            "content": encoded,
        }

        # If the file already exists we must include its SHA
        sha = self._fetch_sha()
        if sha is not None:
            payload["sha"] = sha

        resp = requests.put(
            self._api_url,
            json=payload,
            headers=self._headers,
            timeout=30,
        )
        if resp.status_code == 403 and "Resource not accessible by integration" in resp.text:
            raise RuntimeError(
                "Your GitHub App does not have 'Contents' permission enabled.\n"
                "Two options:\n"
                "  1. GitHub → Settings → Developer settings → GitHub Apps → "
                "your app → Permissions → Contents → Read & write. Then re-run 'pm login'.\n"
                "  2. Generate a Personal Access Token at "
                "https://github.com/settings/tokens/new (check 'repo' scope)\n"
                "     and run: pm config set-token <your-token>"
            )
        resp.raise_for_status()

    def download(self) -> bytes:
        """Retrieve the vault file from GitHub."""
        resp = requests.get(
            self._api_url,
            headers=self._headers,
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        return base64.b64decode(body["content"])

    def exists(self) -> bool:
        """Check whether a vault file is present in the repository."""
        return self._fetch_sha() is not None

    # -- internal -----------------------------------------------------

    def _fetch_sha(self) -> str | None:
        """Return the blob SHA if the file exists, else None.

        Raises a helpful error if the repo is unreachable (doesn't
        exist, is empty, or the token lacks access).
        """
        resp = requests.get(
            self._api_url,
            headers=self._headers,
            timeout=30,
        )
        if resp.status_code == 404:
            repo_check = requests.get(
                f"https://api.github.com/repos/{self.owner}/{self.repo}",
                headers=self._headers,
                timeout=30,
            )

            if repo_check.status_code == 404:
                # Could be: repo doesn't exist, or token lacks scope.
                # Try without auth to see if the repo is public.
                public_check = requests.get(
                    f"https://api.github.com/repos/{self.owner}/{self.repo}",
                    timeout=30,
                )
                if public_check.status_code == 200:
                    # Repo exists but is private — token lacks scope.
                    raise RuntimeError(
                        f"Repository {self.owner}/{self.repo} exists but "
                        f"your token does not have access to it. "
                        f"Run 'pm login' again to grant the 'repo' scope."
                    )
                raise RuntimeError(
                    f"Repository {self.owner}/{self.repo} does not exist "
                    f"(or the token has no access to it). "
                    f"Check the name and run 'pm login' if needed."
                )

            repo_info = repo_check.json()
            if repo_info.get("default_branch") is None:
                raise RuntimeError(
                    f"Repository {self.owner}/{self.repo} is empty. "
                    f"Initialize it with at least one commit (e.g. add a README) "
                    f"before syncing."
                )
            # File doesn't exist yet — that's fine on first push.
            return None
        resp.raise_for_status()
        return resp.json()["sha"]
