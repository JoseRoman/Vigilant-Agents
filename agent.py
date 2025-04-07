import os
from typing import List, Any, Dict
from smolagents import (
    CodeAgent,
    OpenAIServerModel
)
from dotenv import load_dotenv

from GitHubTool import get_github_project_directory_tree, get_github_project_file, get_github_readme, get_github_workflow_names

load_dotenv()

openai_api_key: str = os.getenv("OPENAI_API_KEY", "")

model: OpenAIServerModel = OpenAIServerModel(
    model_id="gpt-4o-mini",
    api_key=openai_api_key
)

github_agent: CodeAgent = CodeAgent(
    tools=[get_github_readme, get_github_project_directory_tree, get_github_project_file, get_github_workflow_names],
    model=model,
    max_steps=10,
    name="search",
    description="Search for a GitHub repository and get information about it. Please NOTE that the argument name is `task`.",
)

security_agent: CodeAgent = CodeAgent(
    tools=[],
    model=model,
    max_steps=10,
    managed_agents=[github_agent],
    additional_authorized_imports=[],
)

# Example usage
if __name__ == "__main__":
    answer: str = security_agent.run("Please confirm if the following project is using any static code analysis tools: https://github.com/nvbn/thefuck")
    print(f"Analysis result: {answer}")