from smolagents import (
    CodeAgent,
    OpenAIServerModel
)

from GitHubTool import get_github_project_directory_tree, get_github_project_file, get_github_readme, get_github_workflow_names

model = OpenAIServerModel(model_id="gpt-4o-mini",api_key="")

web_agent = CodeAgent(
    tools=[get_github_readme, get_github_project_directory_tree, get_github_project_file,get_github_workflow_names],
    model=model,
    max_steps=10,
    name="search",
    description="Search for a GitHub repository and get information about it. Please NOTE that the argument name is `task`.",
)

manager_agent = CodeAgent(
    tools=[],
    model=model,
    max_steps=10,
    managed_agents=[web_agent],
    additional_authorized_imports=[],
)

answer = manager_agent.run("Please confirm if the following project is using any static code analysis tools: https://github.com/nvbn/thefuck")