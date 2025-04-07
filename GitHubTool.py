import base64
from typing import Any, Dict, List, Optional, Tuple, Union
import os
import requests
from requests.exceptions import RequestException
from smolagents import tool
from gitingest import ingest
from github import Auth
from github import Github
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get GitHub token from environment variables, with empty string as fallback
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

@tool
def get_github_workflow_names(owner: str, repo: str) -> List[str]:
    """
    Fetches the names of all workflow jobs in a GitHub repository.

    This function is particularly useful for detecting if the repository
    is using a static application security testing (SAST) solution, such
    as CodeQL, Semgrep, or other security scanning tools, even if they are
    dynamically generated and not explicitly defined in the repository files.

    Args:
        owner: The owner of the GitHub repository.
        repo: The name of the GitHub repository.

    Returns:
        List[str]: A list of workflow job names in the repository.

    Example Use Case:
        This function can be used to check for security-related workflows
        by looking for names like "CodeQL", "Security Scan", or "SAST Scan".
    """
    auth: Auth.Token = Auth.Token(GITHUB_TOKEN)
    g: Github = Github(auth=auth)

    try:
        repository = g.get_repo(f"{owner}/{repo}")

        # Get all workflows in the repository
        workflows = repository.get_workflows()

        return [workflow.name for workflow in workflows]

    except Exception as e:
        return [f"Error: {str(e)}"]

@tool
def get_github_project_file(owner: str, repo: str, path: str) -> str:
    """
    Fetches the content of a file from a GitHub repository.

    Args:
        owner: The owner of the GitHub repository.
        repo: The name of the GitHub repository.
        path: The path to the file in the GitHub repository.

    Returns:
        str: The content of the file in plain text (decoded from base64),
             or an error message if the request fails.
    """

    auth: Auth.Token = Auth.Token(GITHUB_TOKEN)
    g: Github = Github(auth=auth)

    try:
        # Get the repository
        repository = g.get_repo(f"{owner}/{repo}")

        # Get the file content
        content = repository.get_contents(path)

        return content.decoded_content

    except Exception as e:
        return f"An error occurred while fetching the file: {str(e)}"

@tool
def get_github_project_directory_tree(repository_url: str) -> str:
    """
    Fetches the directory tree of a GitHub repository.

    Args:
        repository_url: The URL of the GitHub repository.

    Returns:
        str: The directory tree of the GitHub repository (repository files), or an error message if the request fails.

    """
    try:
        MAX_FILE_SIZE: int = 1 * 1024 * 1024  # 1 MB
        #EXCLUDE_PATTERNS = ["*.test.js", "*.spec.js", "*.test.ts", "*.spec.ts", "*.test.py", "*.spec.py", "test/", "tests/"]
        summary, tree, content = ingest(repository_url, max_file_size=MAX_FILE_SIZE)
        return tree
    except Exception as e:
        return f"An error occurred while fetching the directory tree: {str(e)}"

@tool
def get_github_readme(owner: str, repo: str) -> str:
    """
    Fetches the README file from a GitHub repository using GitHub's API.

    Args:
        owner: The owner of the GitHub repository.
        repo: The name of the GitHub repository.

    Returns:
        str: The content of the README file in plain text (decoded from base64),
             or an error message if the request fails.
    """
    url: str = f"https://api.github.com/repos/{owner}/{repo}/readme"
    headers: Dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    try:
        # Send a GET request to GitHub API
        response: requests.Response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for non-200 responses

        # Parse the JSON response
        data: Dict[str, Any] = response.json()

        # Decode the base64 README content
        readme_content: str = base64.b64decode(data["content"]).decode("utf-8")

        return readme_content.strip()

    except RequestException as e:
        return f"Error fetching README from GitHub: {str(e)}"
    except KeyError:
        return "Error: README content not found in the API response."
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"
