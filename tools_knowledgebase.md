I’ll compile an extensive list of static code analysis tools across multiple programming languages, including both open-source and commercial options. The configuration details will focus on commonly used settings (e.g., `.gitlab-ci.yml`, `.eslintrc.json`, `pylintrc`, etc.). The final document will be structured in a way that facilitates vectorization, ensuring easy parsing for your AI agents.

I’ll notify you once the document is ready.

# Static Code Analysis Tools

Static code analysis tools examine source code to detect bugs, enforce coding standards, and identify security vulnerabilities without executing the program. Below is an extensive list of such tools across multiple programming languages (open-source and commercial), along with common configuration details (e.g. CI integration via `.gitlab-ci.yml`, linter config files like `.eslintrc.json`, `pylintrc`, `.pre-commit-config.yaml`, etc.) for each tool. This structured overview is organized by category for easy reference and vectorization.

## Multi-Language Static Analysis Tools

### SonarQube / SonarCloud 
- **Description:** SonarQube is a popular platform for continuous code quality inspection, supporting numerous languages. It identifies code smells, bugs, and security issues. SonarQube is open-source (Community Edition) with paid enterprise options, and SonarCloud is the cloud-hosted commercial service.
- **Languages:** Supports dozens of languages (Java, C#, JavaScript, C/C++, Python, PHP, Ruby, Go, and more) ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=Coverity%20%20%202023,and%20to%20the%20specification%20of)). 
- **Configuration:** Typically configured via a `sonar-project.properties` file in the project root to set project key, name, version, source directories, etc. For example: 
  ```properties
  # sonar-project.properties
  sonar.projectKey=my-project
  sonar.projectName=My Project
  sonar.sources=src
  sonar.sourceEncoding=UTF-8
  ``` 
  This defines a unique project key and source paths ([sonarqube - How do I use, or set up sonar-project.properties file? - Stack Overflow](https://stackoverflow.com/questions/34071879/how-do-i-use-or-set-up-sonar-project-properties-file#:~:text=,project)). Many settings can also be managed through the SonarQube UI or passed as CLI parameters. 
- **CI Integration:** Use the SonarScanner CLI in CI (e.g. a job in `.gitlab-ci.yml` running `sonar-scanner` with the project properties). SonarQube analysis can be triggered in a CI pipeline after build/test stages. For GitLab, including SonarScanner in a CI job with appropriate environment variables (like login token and host URL) is common.

### Semgrep 
- **Description:** Semgrep is an open-source multi-language static analysis tool focused on pattern-based rules. It’s often used for finding security vulnerabilities and enforcing code standards via custom rules.
- **Languages:** Supports many languages (C, Python, Java, JavaScript, Go, Ruby, etc.) by using language-specific rule patterns.
- **Configuration:** Semgrep rules are written in YAML files. You can either use the extensive Semgrep rules registry or write custom rules in a `.semgrep.yml` (or similar) config. This file specifies which rules (patterns) to run on which paths. Example snippet:
  ```yaml
  rules:
    - id: no-eval
      pattern: eval(...)
      message: Avoid using eval()
      languages: [python, javascript]
      severity: ERROR
  ```
  Semgrep will run these rules to flag any code matching the patterns.
- **CI Integration:** Semgrep can be run via its CLI (`semgrep --config <ruleset>`). In GitLab CI, use the official `returntocorp/semgrep` Docker image in a job that runs `semgrep` on the codebase. Semgrep outputs findings which can be collected as artifacts or posted as comments via integrations.

### CodeQL 
- **Description:** CodeQL (from GitHub) is an open-source semantic code analysis engine that treats code as data. It allows writing queries to find vulnerabilities and patterns in code. It’s widely used for security analysis (and powers GitHub’s code scanning).
- **Languages:** Supports multiple languages including C/C++, C#, Go, Java, JavaScript/TypeScript, Python, Ruby, etc.
- **Configuration:** CodeQL analyses are often configured via CI workflows rather than project config files. For GitHub, one uses a GitHub Actions workflow (`codeql-analysis.yml`) which specifies the languages to analyze and runs the CodeQL CLI to scan code and interpret queries. Custom CodeQL queries can be provided in a repository. There isn’t a single static config file inside the codebase; instead, configuration is done in the CI pipeline or CodeQL CLI commands (selecting query packs, specifying paths to include/exclude).
- **CI Integration:** On GitHub, enabling “Code scanning” with CodeQL sets up a workflow. On GitLab or others, one can run the CodeQL CLI manually in a CI job (after installing CodeQL). For example, in `.gitlab-ci.yml` one might have a job that uses a CodeQL container to initialize a database for each language and run queries, then upload the results.

### Coverity 
- **Description:** Coverity is a commercial static analysis tool by Synopsys that deeply analyzes code for defects and security issues. It’s known for strong C/C++ analysis and also supports other languages. Coverity can detect memory errors, concurrency issues, etc., with a focus on quality and security.
- **Languages:** Wide language support, including C, C++, C#, Java, JavaScript/TypeScript, Python, PHP, Ruby, and more ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=Coverity%20%20%202023,and%20to%20the%20specification%20of)) ([13 Best Static Code Analysis Tools For 2025 - Qodo](https://www.qodo.ai/blog/best-static-code-analysis-tools/#:~:text=,for%20developers%20contributing%20to%20the)). Coverity is free for qualified open-source projects ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=Coverity%20%20%202023,and%20to%20the%20specification%20of)).
- **Configuration:** Coverity analysis is typically configured outside the code via command-line parameters or build integration. The usual flow is to do a **build capture** (using `cov-build` to compile the project and produce an intermediate representation) and then analyze with `cov-analyze`. Configuration involves specifying project-specific options in a configuration file or Coverity’s web interface (Coverity Connect). For instance, one might have a JSON or properties file for Coverity specifying which checkers to enable/disable, or you configure these in the Coverity server portal.
- **CI Integration:** Integrates into CI by adding a build stage wrapped with Coverity’s build capture, then uploading results to a Coverity server. For example, a GitLab CI job might use a Coverity provided image, run `cov-build --dir output make`, then `cov-analyze --dir output` and `cov-submit` to send results. Coverity also integrates with CI systems like Jenkins and has plugins to fail builds on new defects.

### Fortify Static Code Analyzer (SCA) 
- **Description:** Fortify SCA (now under OpenText, formerly Micro Focus) is a commercial SAST tool focusing on security vulnerabilities. It scans source code for a vast range of security issue categories.
- **Languages:** Supports 30+ major programming languages and their frameworks ([OpenText Fortify Static Code Analyzer | OpenText - Micro Focus](https://www.microfocus.com/media/brief/opentext-fortify-static-code-analyzer-brief-en.pdf#:~:text=OpenText%E2%84%A2%20Fortify%E2%84%A2%20Static%20Code%20Analyzer,security%20vulnerabilities%20in%20source%20code)) ([13 Best Static Code Analysis Tools For 2025 - Qodo](https://www.qodo.ai/blog/best-static-code-analysis-tools/#:~:text=vulnerabilities%20across%2035%2B%20programming%20languages%2C,vulnerabilities%20before%20they%20become%20critical)) (Java, C/C++, C#, VB.NET, PHP, Python, Ruby, JavaScript, Swift, Kotlin, and many more, covering web, desktop, and mobile).
- **Configuration:** Fortify SCA is typically run via its CLI (`sourceanalyzer`). Configuration can be done through Fortify project files (`.properties` or Fortify **Rulepacks** selection) or command-line flags. Common settings include specifying the source code encoding, turning certain rules on/off, and setting an analysis **build ID**. You might use a Fortify configuration file (`fortify.properties`) to declare which folders to scan or not, but often it’s configured by CLI per scan.
- **CI Integration:** Often integrated by adding a CI job that invokes Fortify. For example, in Jenkins or GitLab, run `sourceanalyzer -b <buildid> -scan -f results.fpr <source_paths>` after a build step. The resulting FPR file (Fortify Project Results) can then be uploaded to Fortify Software Security Center (SSC) or reviewed with Fortify tools. Fortify can also be incorporated earlier in development via IDE plugins.

### Checkmarx CxSAST 
- **Description:** Checkmarx CxSAST is a commercial static application security testing tool. It scans source code for security vulnerabilities without requiring the code to be compiled ([GitHub - analysis-tools-dev/static-analysis: ⚙️ A curated list of static analysis (SAST) tools and linters for all programming languages, config files, build tools, and more. The focus is on tools which improve code quality.](https://github.com/analysis-tools-dev/static-analysis#:~:text=presentation)).
- **Languages:** Very broad language support – Checkmarx SAST supports 35+ languages and 80+ frameworks ([SAST Scan: Static Application Security Testing - Checkmarx](https://checkmarx.com/cxsast-source-code-scanning/#:~:text=Checkmarx%20SAST%20supports%20over%2035,critical%20applications)) (covering modern and legacy languages, from Java, C#, JavaScript/TypeScript, C/C++, Python, PHP, to COBOL and more).
- **Configuration:** Configuration is usually handled in the Checkmarx interface or via a CxCLI command. You define project settings like included/excluded files and the set of rules (preset) to use. A local config file is not common; instead, parameters are passed when invoking scans (e.g., project name, preset name, etc.). For automation, one can use the Checkmarx CLI with a CxSAST configuration XML or a command-line flags approach.
- **CI Integration:** CxSAST integrates via plugins (Jenkins, GitLab, Azure DevOps) or via the CLI. In a `.gitlab-ci.yml`, you might use a Docker image for CxSAST or call the Checkmarx REST API. For instance, a CI job can use `Checkmarx CxFlow` or the Checkmarx CLI to trigger a scan after code is pushed, then fail the pipeline if high-severity issues are found. Checkmarx can also be configured in *incremental scan* mode to analyze only changed code for faster feedback.

### Veracode Static Analysis 
- **Description:** Veracode is a cloud-based static and dynamic analysis platform (commercial). Here we focus on its static code analysis, which is part of its holistic security scanning offerings. Developers upload binaries or source, and Veracode scans for vulnerabilities.
- **Languages:** Supports more than 30 languages (covering all widely-used languages for web, mobile, and desktop apps) and 100+ frameworks ([Languages & Frameworks - Veracode](https://www.veracode.com/languages-framework#:~:text=Languages%20%26%20Frameworks%20,100%2B%20industry%20frameworks%20%2C%20including)) – e.g., Java, C#, C/C++, JavaScript, Python, Ruby, PHP, Go, and others.
- **Configuration:** Veracode static analysis doesn’t use an in-repo config file; instead, configuration is done via the Veracode platform settings or scanning profiles. You typically provide scanning options (like which modules to include, scan timeouts, etc.) when starting a scan. If using Veracode’s Pipeline Scan (for CI), you might have a small config JSON/YAML to define paths to include or exclude.
- **CI Integration:** Often done via Veracode’s Jenkins plugin or their REST API using a wrapper script. In GitLab CI, one could use Veracode’s Java CLI wrapper (`veracode.jar`) in a job to upload code and initiate a scan. Example script snippet:
  ```yaml
  veracode_scan:
    image: openjdk:8-jdk
    script:
      - wget https://repo.veracode.com/veracode.jar
      - java -jar veracode.jar -vid $VERACODE_ID -vkey $VERACODE_KEY -action uploadandscan -appname "MyApp" -createprofile false -scantimeout 60 -file target/myapp.war
  ```
  This would upload a WAR and start scanning. After completion, results are viewable on the Veracode platform (and can be downloaded or used to gate builds via API).

### Codacy 
- **Description:** Codacy is a cloud-based code quality platform (commercial, with free tier for open-source) that runs static analysis, code style checks, coverage, and more. It aggregates results from multiple linters and analysis tools.
- **Languages:** Supports 40+ programming languages with various underlying analysis engines ([Supported languages and tools - Codacy docs](https://docs.codacy.com/getting-started/supported-languages-and-tools/#:~:text=Supported%20languages%20and%20tools,code%20platforms%2C%20Codacy)). For each language, Codacy uses well-known linters (e.g., ESLint for JS, Pylint/Flake8 for Python, PMD/Checkstyle for Java, etc.) ([Supported languages and tools - GitHub](https://github.com/codacy/docs/blob/7a222aa44f3d04491698d77c645ac4fd8d63c975/docs/getting-started/supported-languages-and-tools.md#:~:text=List%20of%20tools%20that%20Codacy,metrics%20for%20most%20programming%20languages)).
- **Configuration:** Codacy can be largely configured via its UI (selecting which rules or tools to enable/disable). Optionally, a codacy configuration file (like `.codacy.yml`) can be added to customize the analysis (e.g., to ignore certain files or directories, set code patterns to skip). Most commonly, projects just rely on Codacy’s detection of languages and default tool configurations. If needed, project-level tool configs (like an `.eslintrc.json` or `pylintrc`) are respected by Codacy’s analysis.
- **CI Integration:** Codacy typically runs externally (triggered by pushing code to a repository it monitors). However, you can integrate results by failing the CI build based on Codacy status (through Codacy’s API or status checks on GitHub/GitLab). Some teams use Codacy’s **Coverage** reporter or **Quality** gate in the pipeline to enforce thresholds. Direct use in `.gitlab-ci.yml` might involve using Codacy’s API token to invoke analyses or download results, but usually Codacy runs on its own infrastructure after code push.

### CodeClimate 
- **Description:** CodeClimate is another platform for automated code review and quality metrics. It provides maintainability analysis, test coverage tracking, and can run a variety of analysis engines (including security scanning via plugins).
- **Languages:** Supports several languages out-of-the-box for maintainability checks (Ruby, Python, PHP, JavaScript, Java, TypeScript, Go, Swift, Scala, Kotlin, C#, etc.) ([Supported Languages for Maintainability - Code Climate](https://docs.codeclimate.com/docs/supported-languages-for-maintainability#:~:text=Supported%20Languages%20for%20Maintainability%20,in%20addition%20to)). Through its plugin “engines,” it can run tools for many languages.
- **Configuration:** CodeClimate can be configured with a `.codeclimate.yml` file in the repo. This file specifies which analysis engines to enable and their settings. For example, enabling the “ESLint” engine or “PHPCodeSniffer” engine, and specifying paths to include/exclude. A sample `.codeclimate.yml` might include:
  ```yaml
  plugins:
    eslint:
      enabled: true
    rubocop:
      enabled: true
  ratings:
    paths:
      - "**.js"
      - "**.rb"
  ```
  This turns on ESLint for JS files and RuboCop for Ruby files. If no config file is present, CodeClimate allows configuration via their UI.
- **CI Integration:** CodeClimate can run in CI using their Docker image. GitLab’s built-in **Code Quality** template historically was based on CodeClimate’s engines. In `.gitlab-ci.yml`, you might use:
  ```yaml
  code_quality:
    image: codeclimate/codeclimate
    script:
      - codeclimate analyze -f json > gl-code-quality-report.json
    artifacts:
      paths: [gl-code-quality-report.json]
  ```
  This generates a Code Quality report artifact that GitLab can interpret. CodeClimate’s online service can also be used by pushing the repo to it and reading results from the platform (with status checks for PRs/MRs).

### JetBrains Qodana 
- **Description:** Qodana is JetBrains’ static analysis platform, essentially running IntelliJ IDEA’s inspections via CI. It packages language-specific linters (each Qodana “linter” corresponds to a JetBrains IDE code inspection set, e.g., Qodana for JVM, Qodana for Python, etc.).
- **Languages:** There are Qodana linters for many languages and technologies (Java/Kotlin, Python, PHP, JavaScript/TypeScript, .NET, Android, etc.), covering more than 60 technologies in total ([Qodana 2023.1: Flexible Profile Configuration ... - The JetBrains Blog](https://blog.jetbrains.com/qodana/2023/04/qodana-2023-1/#:~:text=Qodana%202023,analyze%20unlimited%20lines%20of%20code)).
- **Configuration:** Uses a YAML config file (`qodana.yaml` by default in project root) for custom settings. In `qodana.yaml`, you can specify which inspections to disable or enable, set thresholds for issues, and configure baseline files (to ignore existing issues). If no config is provided, Qodana uses JetBrains’ default inspection profile for that language. Example `qodana.yaml`:
  ```yaml
  profile: Qodana.Recommended  # use a built-in profile
  ignore:
    - "src/generated/**"
  linter:
    cache: false
  ```
  You can also supply an **inspection profile** file from IntelliJ or use command-line options to configure Qodana runs.
- **CI Integration:** Qodana provides Docker images (e.g., `jetbrains/qodana-jvm` for Java projects). In a CI pipeline, you run the Docker image against your code. For GitLab:
  ```yaml
  qodana_analysis:
    image: jetbrains/qodana-jvm:2024.3
    script:
      - ./qodana.sh -d . -o qodana-results
    artifacts:
      paths: [qodana-results]
  ```
  This would analyze the current directory and output results (which could be viewed as an HTML report or processed). Qodana can also upload results to Qodana Cloud for centralized viewing. It is a newer entry; JetBrains IDE users find it useful to enforce the same inspections in CI as in their IDE.

*(The above multi-language tools often integrate into development platforms and CI/CD. Next, we list tools by specific languages, focusing on their typical usage and configurations.)*

## Python Static Analysis Tools

### Pylint 
- **Description:** Pylint is a comprehensive linter for Python code that checks for errors, enforces coding standards, and offers refactoring suggestions. It assigns codes to its messages (e.g., `C0111` for missing docstring) and can be quite strict.
- **Type:** Open-source (PyCQA project).
- **Configuration:** Highly configurable via a `pylintrc` file. You can generate a template config with `pylint --generate-rcfile`. Projects typically include a `.pylintrc` in the repo root to adjust settings (or put config in `pyproject.toml` under `[tool.pylint]`). In the config, you can enable/disable specific checks and set options like naming conventions, line length, etc. For example:
  ```ini
  [MESSAGES CONTROL]
  disable = C0111,  # disable missing-docstring
            W0703   # disable broad-except
  [FORMAT]
  max-line-length = 100
  [BASIC]
  good-names=i,j,k  # allow these short variable names
  ``` 
  Pylint will search for `pylintrc` or `.pylintrc` in the current directory (or parent directories) by default ([pylint - How do I create a pylintrc file - Stack Overflow](https://stackoverflow.com/questions/22448731/how-do-i-create-a-pylintrc-file#:~:text=,rcfile%3D%3Cwherever%20I%20want)). It also recognizes `setup.cfg` or `pyproject.toml` for config if sections are properly named ([Running Pylint - Pylint 4.0.0-dev0 documentation](https://pylint.pycqa.org/en/latest/user_guide/usage/run.html#:~:text=least%20one%20)).
- **CI Integration:** Running Pylint in CI is straightforward. For GitLab CI, add a job using a Python image that installs pylint and runs it. For example, a `.gitlab-ci.yml` snippet:
  ```yaml
  lint:python:
    image: python:3.9
    script:
      - pip install pylint
      - pylint my_package/ tests/
  ```
  Or as shown below, a job named `test:pylint` installing Pylint and scanning all `.py` files ([
                    GitLab : Automatically testing your Python project |
                cylab.be](https://cylab.be/blog/18/gitlab-automatically-testing-your-python-project#:~:text=test%3Apylint%3A%20image%3A%20python%3A3.6%20script%3A%20,classes%3D_socketobject%20%2A.py)):
  ```yaml
  test:pylint:
    image: python:3.6
    script:
      - pip install pylint --quiet
      - pylint --ignored-classes=_socketobject *.py
  ``` 
  This example uses a specific Pylint option to ignore certain false positives ([
                    GitLab : Automatically testing your Python project |
                cylab.be](https://cylab.be/blog/18/gitlab-automatically-testing-your-python-project#:~:text=script%3A%20,classes%3D_socketobject%20%2A.py)). The job will fail if Pylint finds errors above the threshold.
- **Pre-commit Integration:** Pylint can be run as a Git pre-commit hook via the [pre-commit framework](https://pre-commit.com). In `.pre-commit-config.yaml`, include a repo for Pylint, for example:
  ```yaml
  - repo: https://github.com/PyCQA/pylint
    rev: v2.17.4
    hooks:
      - id: pylint
        args: [--errors-only]  # only flag errors on commit
  ```
  This ensures Pylint runs on changed files before commit.

### Flake8 
- **Description:** Flake8 is a fast, extensible wrapper around PyFlakes, pycodestyle (PEP8 checks), and McCabe complexity checker ([GitHub - analysis-tools-dev/static-analysis: ⚙️ A curated list of static analysis (SAST) tools and linters for all programming languages, config files, build tools, and more. The focus is on tools which improve code quality.](https://github.com/analysis-tools-dev/static-analysis#:~:text=,mccabe)). It catches syntax errors, style issues, and simple programming errors. Many plugins are available to extend Flake8’s checks.
- **Type:** Open-source (PyCQA).
- **Configuration:** Flake8 can read configuration from a few places: `setup.cfg`, `tox.ini`, or a dedicated `.flake8` file in the project root. It looks for a `[flake8]` section in those INI-format files ([Configuring Flake8 — flake8 7.1.0 documentation - PyCQA](https://flake8.pycqa.org/en/latest/user/configuration.html#:~:text=Configuration%20Locations%20Flake8%20supports%20storing,options%20which%20can%20alter%20this)). Common settings include `ignore` or `select` lists of error codes, `max-line-length`, and `exclude` patterns for files. Example `.flake8`:
  ```ini
  [flake8]
  ignore = E203, W503  # ignore certain PEP8 warnings
  max-line-length = 88
  exclude = .git,__pycache__,old,build,dist
  ```
  This config ignores two specific style issues and sets max line length to 88 (suitable for Black formatter compatibility). Flake8 will stop at the first config file found in the directory hierarchy ([python - flake8 not picking up config file - Stack Overflow](https://stackoverflow.com/questions/28436382/flake8-not-picking-up-config-file#:~:text=This%20works%20because%20flake8%20looks,but%20at%20least%20flake8)).
- **CI Integration:** Very similar to Pylint, you can run Flake8 in CI with a Python environment. For instance, in GitLab CI:
  ```yaml
  lint:flake8:
    image: python:3.10
    script:
      - pip install flake8
      - flake8 .
  ```
  If the project has a `setup.cfg` or `.flake8` with custom rules, those will be applied. Flake8 exits with a non-zero status if issues are found, failing the job.
- **Pre-commit Integration:** Flake8 is commonly used with pre-commit hooks. Using pre-commit, you’d add something like:
  ```yaml
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: flake8
  ```
  to your `.pre-commit-config.yaml`. For example, a combined pre-commit config for Black and Flake8 might look like ([How to setup your project with pre-commit, black, and flake8 - DEV Community](https://dev.to/m1yag1/how-to-setup-your-project-with-pre-commit-black-and-flake8-183k#:~:text=,id%3A%20flake8)):
  ```yaml
  repos:
    - repo: https://github.com/psf/black
      rev: 23.1.0
      hooks:
        - id: black
    - repo: https://github.com/pre-commit/pre-commit-hooks
      rev: v4.4.0
      hooks:
        - id: flake8
  ``` 
  This will run Black (auto-formatting) and then Flake8 on the changed files upon commit, using any config from `.flake8` or equivalent files.

### MyPy 
- **Description:** MyPy is a static type checker for Python. While not a bug-finder in the traditional sense, it analyzes your code against type hints (PEP 484) to find type errors and inconsistencies, essentially performing static analysis for type correctness.
- **Type:** Open-source.
- **Configuration:** MyPy can be configured via a `mypy.ini` or `pyproject.toml` (or `setup.cfg`) ([The mypy command line - mypy 1.15.0 documentation - Read the Docs](https://mypy.readthedocs.io/en/stable/command_line.html#:~:text=The%20mypy%20command%20line%20,syntax%20of%20configuration%20files)). The config file allows setting global options such as python version, disallow-untyped defs, ignore missing imports, strictness flags, and which files or patterns to include/exclude. An example **mypy.ini**:
  ```ini
  [mypy]
  python_version = 3.9
  strict = True
  exclude = tests/  # don't type-check tests
  ignore_missing_imports = True
  ```
  By default, MyPy will read `mypy.ini` or `.mypy.ini` in the current directory, or a `[tool.mypy]` table in `pyproject.toml` ([The mypy command line - mypy 1.15.0 documentation - Read the Docs](https://mypy.readthedocs.io/en/stable/command_line.html#:~:text=By%20default%20settings%20are%20read,syntax%20of%20configuration%20files)).
- **CI Integration:** Running MyPy in CI ensures type checking is part of the pipeline. For example:
  ```yaml
  typecheck:
    image: python:3.9
    script:
      - pip install mypy
      - mypy .
  ```
  If any type errors are found, MyPy returns a non-zero exit code, failing the job. Teams often use MyPy with a strict configuration to catch bugs like passing wrong argument types.
- **Pre-commit Integration:** There is a pre-commit hook for MyPy as well. Example in `.pre-commit-config.yaml`:
  ```yaml
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.4.1
    hooks:
      - id: mypy
  ```
  This will run MyPy on staged files (or the whole project, depending on hook settings) prior to commits.

### Bandit 
- **Description:** Bandit is a security-focused linter for Python code (from OpenStack Security). It examines Python code for common security issues (hardcoded passwords, SQL injection, use of insecure functions, etc.).
- **Type:** Open-source (PyCQA).
- **Configuration:** Bandit can run with default settings, but supports an optional config. Projects can include an INI file named `.bandit` in the repo to specify command-line args to always use ([Configuration — Bandit documentation - Read the Docs](https://bandit.readthedocs.io/en/latest/config.html#:~:text=Configuration%20Bandit%20Settings%20,The%20currently%20supported%20arguments%20are)). More advanced configuration (like selecting specific tests or overriding test parameters) can be done with a YAML config file, but you must explicitly pass it via `-c config.yaml` ([Configuration — Bandit documentation](https://bandit.readthedocs.io/en/1.7.4/config.html#:~:text=Configuration%20%E2%80%94%20Bandit%20documentation%20To,default%20configurations%20of%20those%20tests)). In practice, many simply run Bandit with defaults or specify a baseline file for known issues. Example Bandit config (YAML):
  ```yaml
  profiles:
    my_profile:
      include: [B101, B102]  # only run these tests
  ```
  Or an INI `.bandit` file to always skip certain tests:
  ```ini
  [bandit]
  skips: B101,B104
  ```
  which tells Bandit to skip those tests every run ([What is the way to ignore/skip some issues from python bandit security ...](https://stackoverflow.com/questions/52596576/what-is-the-way-to-ignore-skip-some-issues-from-python-bandit-security-issues-re#:~:text=So%20if%20you%20want%20to,additional%20comments%20in%20the%20code)).
- **CI Integration:** Bandit can be installed (`pip install bandit`) and run in CI. A typical command: `bandit -r . -x tests/ -o bandit_report.json -f json`. This recursively checks the repo, excluding tests, outputting a JSON report. In GitLab CI, one might define a Bandit job that uploads the JSON report as an artifact for review. If you want to fail the pipeline on any Bandit findings above a certain severity, you could parse Bandit’s exit code or use the `--exit-zero` flag and post-process the JSON.
- **Pre-commit Integration:** Bandit is included in the pre-commit hooks index. You can add:
  ```yaml
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.4
    hooks:
      - id: bandit
  ```
  to `.pre-commit-config.yaml`. This will run Bandit on committed Python files. (Note: If Bandit needs a config file, ensure the hook includes the `-c` argument as needed, since by default it won’t auto-load a `.bandit.yml` without `-c`.)

### Other Python Linters/Tools 
- **flake8 Plugins:** There are many flake8 plugins (for example, **flake8-bugbear** for likely bugs, **flake8-import-order**, etc.). These are configured via the same Flake8 config file under plugin-specific options.
- **pydocstyle (PEP257):** For docstring style checking. Often integrated via flake8 (as `flake8-docstrings`) or run standalone with a `pydocstyle.ini`.
- **Black (formatter):** While not a static *analysis* tool, Black is often used alongside these linters to auto-format code. It reads configuration from `pyproject.toml`.
- **Prospector:** A meta-tool that wraps Pylint, mccabe, and others to provide a combined report. Uses a `.prospector.yaml` config.
- **Radon:** Measures code complexity (Cyclomatic Complexity, etc.), sometimes used to fail builds if complexity is too high.
- **Safety/Pip-audit:** For dependency vulnerability scanning (not static code analysis of your code, but related to code security in Python).

Python projects often use a combination: e.g., Black (formatting), isort (import sorting), Flake8 or Pylint (linting), MyPy (type checking), and Bandit (security). Tools like **pre-commit** help tie these together by running them on each commit, using a config like: 

```yaml
repos:
- repo: https://github.com/pre-commit/pre-commit-hooks
  rev: v4.4.0
  hooks:
    - id: flake8
    - id: pretty-format-json
- repo: https://github.com/PyCQA/pylint
  rev: v2.17.4
  hooks:
    - id: pylint
```

This ensures consistency and catches issues early.

## JavaScript/TypeScript Static Analysis Tools

### ESLint 
- **Description:** ESLint is the dominant linter for JavaScript and TypeScript. It is highly configurable and supports custom rules and plugins. ESLint checks for both code quality issues and potential errors (unused variables, undefined variables, etc.), and it can enforce style guidelines.
- **Type:** Open-source.
- **Configuration:** ESLint is configured via a file (e.g. `.eslintrc.json`, `.eslintrc.yml`, or `.eslintrc.js`). In the config, you specify environment (`env`), parser options (especially for TypeScript or newer ECMAScript features), plugins, and rules. A common approach is to extend recommended rule sets:
  ```json
  {
    "env": { "browser": true, "node": true, "es6": true },
    "extends": [
      "eslint:recommended",
      "plugin:@typescript-eslint/recommended"
    ],
    "parser": "@typescript-eslint/parser",
    "plugins": ["@typescript-eslint"],
    "rules": {
      "no-unused-vars": "warn",
      "eqeqeq": "error"
    }
  }
  ```
  This example sets environment globals, extends ESLint’s recommended rules and TS recommended rules, and overrides some specific rules. Using `"extends": "eslint:recommended"` enables a base set of rules for common problems ([How to Setup ESLint .eslintrc Config – Duncan Leung](https://duncanleung.com/how-to-setup-eslint-eslintrc-config-difference-eslint-config-plugin/#:~:text=The%20,configurations%20from%20an%20existing%20configuration)). ESLint also supports placing config in `package.json` under an `"eslintConfig"` field (though separate rc files are more common).
- **CI Integration:** In a Node.js project on GitLab CI, you can use a Node image and run ESLint. For instance:
  ```yaml
  lint:eslint:
    image: node:16
    script:
      - npm ci        # install dependencies including eslint
      - npx eslint .  # run ESLint on the project
  ```
  If ESLint finds any errors (rule violations that are set to “error”), it exits with code 1 causing the CI job to fail. An example GitLab CI job is ([Getting started with Gitlab CI/CD: Eslint - DEV Community](https://dev.to/karltaylor/getting-started-with-gitlab-cicd-eslint-1m80#:~:text=,npm%20i%20eslint)):
  ```yaml
  eslint:
    stage: lint
    image: node:lts
    script:
      - npm install eslint
      - npx eslint .
  ```
  which will install ESLint and run it over the current directory’s code.
- **Pre-commit Integration:** There are pre-commit hooks for ESLint. Typically, one uses the `pre-commit` mirror of ESLint:
  ```yaml
  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v8.37.0
    hooks:
      - id: eslint
  ```
  This assumes ESLint and necessary plugins are in your project’s `node_modules`. Another common approach is using Husky (a Node-specific git hooks tool) to run ESLint on pre-commit or pre-push.
- **TypeScript Support:** ESLint can be used for TypeScript by using `@typescript-eslint/parser` and the associated plugin. TSLint (the old TS linter) is deprecated, so ESLint with TypeScript plugin is the standard. The configuration moves type-checking rules into ESLint’s domain (with rules in `@typescript-eslint` plugin).
- **Additional:** ESLint has an autofix feature for many rules (`eslint --fix`). Config files can be hierarchical, and you can override settings for specific directories or file patterns within the config. 

### JSHint 
- **Description:** JSHint is an older linter for JavaScript. It was one of the first tools to check JS code for errors and style issues (a successor to JSLint with a more permissive approach). Its usage has declined in favor of ESLint, but it’s still available.
- **Type:** Open-source.
- **Configuration:** JSHint uses a `.jshintrc` file (JSON format) to configure which checks to enable or disable. For example:
  ```json
  {
    "undef": true,      // warn on usage of undefined variables
    "unused": true,     // warn on unused variables
    "browser": true,    // define browser globals
    "esversion": 6,     // allow ES6 syntax
    "globals": {        // pre-define global variables
      "angular": false
    }
  }
  ```
  This sets some typical options. If no config file is present, JSHint has defaults, but generally a `.jshintrc` at project root (or even user home) is provided.
- **CI Integration:** Much like ESLint, you would run `jshint` on your files. For example:
  ```yaml
  lint:jshint:
    image: node:18
    script:
      - npm install -g jshint
      - jshint **/*.js
  ```
  Ensure the `.jshintrc` is checked in so that JSHint uses your desired settings. JSHint’s exit code will be non-zero if issues are found (unless you use `--verbose` which doesn’t alter exit code logic).
- **Usage Note:** JSHint is simpler than ESLint (fewer rules and no plugin system). It doesn’t support TypeScript or JSX parsing, so ESLint (with appropriate parser) is typically required for modern JS frameworks. If a project still uses JSHint, the config mainly toggles core checks.

### TSLint (Deprecated) 
- **Description:** TSLint was the dedicated linter for TypeScript before ESLint became the unified solution. It is now deprecated and the recommendation is to use ESLint with TypeScript.
- **Configuration:** TSLint used a `tslint.json` config file. It defined rule configurations similarly to ESLint. For example:
  ```json
  {
    "defaultSeverity": "error",
    "extends": "tslint:recommended",
    "rules": {
      "quotemark": [true, "single"],
      "semicolon": [true, "always"]
    }
  }
  ```
  However, since TSLint is no longer maintained (as of 2019/2020), new projects should avoid it.
- **Migration:** Tools (`tslint-to-eslint-config`) exist to convert a `tslint.json` setup to an ESLint configuration. If you encounter TSLint in older projects, migrating to ESLint is advised.
- **CI Integration:** If still in use, it would be run with `npx tslint -p tsconfig.json` (for example) in CI. But again, modernization involves replacing this with ESLint.

### Prettier 
- **Description:** Prettier is an opinionated code formatter (not exactly a static analysis tool, but often part of the code quality toolchain). It ensures consistent code style (indentation, quotes, etc.) automatically.
- **Configuration:** Prettier can be configured minimally via a `.prettierrc` (or `prettier.config.js`) for things like print width, tab width, semicolons, quotes. Many teams use it with default settings. Prettier is often integrated with ESLint (either by disabling conflicting ESLint rules or using `eslint-plugin-prettier` to report format issues).
- **Usage:** Run `prettier --check .` in CI to ensure code is formatted (or `--write` to auto-fix). Prettier is frequently run as a pre-commit hook to auto-fix formatting on commit.

### Others (JS/TS)
- **Flow:** A static type checker for JavaScript by Facebook. It uses a `.flowconfig` file. However, Flow’s popularity has waned with TypeScript’s rise.
- **ESLint Plugins:** There are many plugins for specific frameworks or checks: e.g., `eslint-plugin-react` for React specific linting, `eslint-plugin-security` for security anti-patterns in JS, etc. These are configured in the ESLint config file (under `plugins` and `rules`).
- **Security Scanners:** Tools like **Retire.js** or **npm audit** focus on vulnerabilities in dependencies rather than code. **Semgrep** (mentioned earlier) also has JavaScript rules.
- **Stylelint:** For CSS/SCSS/etc, Stylelint is a static analysis tool to enforce style conventions in stylesheets. It uses a `.stylelintrc` config (JSON or YAML) and can be part of front-end build processes.

In modern JavaScript/TypeScript projects, ESLint is the primary static analysis tool, often combined with Prettier (and TypeScript’s own compiler checks). Running `tsc --noEmit` in CI can act as a static analysis step for type correctness (with the `strict` flags in `tsconfig.json` ensuring potential issues are caught).

## Java Static Analysis Tools

### Checkstyle 
- **Description:** Checkstyle is a development tool to help programmers write Java code that adheres to a coding standard. It primarily focuses on coding style, formatting, and some simple bug patterns. It can catch things like naming conventions, braces usage, imports order, etc.
- **Type:** Open-source (LGPL).
- **Configuration:** Configured via an XML file (often named `checkstyle.xml`). This file defines which rules (Checks) to apply. Checkstyle comes with default rulesets like Sun’s Java conventions and Google’s Java style (e.g., `google_checks.xml`) ([Configuration – checkstyle](https://checkstyle.org/config.html#:~:text=If%20Checkstyle%20rejects%20your%20configuration,that%20checks%20the%20coding%20conventions)). Teams often start with one of these and customize. A Checkstyle config XML starts with a `<module name="Checker">` root and includes various `<module name="RuleName">` entries. For example:
  ```xml
  <module name="Checker">
    <module name="TreeWalker">
      <module name="WhitespaceAround"/>
      <module name="AvoidStarImport"/>
      <!-- etc... -->
    </module>
  </module>
  ```
  You include or exclude rules by adding or removing module entries. The config can also suppress certain patterns or files. Projects typically place `checkstyle.xml` at the root or in a `config/` directory and reference it from the build tool.
- **CI/Build Integration:** Checkstyle is often run via a Maven or Gradle plugin. For Maven, the Checkstyle plugin can be configured in `pom.xml` to use the custom ruleset (and possibly fail the build on violations). For example, in Maven:
  ```xml
  <plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-checkstyle-plugin</artifactId>
    <version>3.2.2</version>
    <configuration>
      <configLocation>checkstyle.xml</configLocation>
      <failsOnError>true</failsOnViolation>true</failsOnViolation>
    </configuration>
    <executions> ... </executions>
  </plugin>
  ```
  Similarly, in Gradle, you can use the Checkstyle plugin and point it to `config/checkstyle/checkstyle.xml`. The CI will then run these checks as part of the normal build. Alternatively, one can directly invoke Checkstyle via its CLI (`java -jar checkstyle.jar -c checkstyle.xml src/`). 
- **Common Rules:** Enforcing Javadoc on public classes/methods, line length limits, naming conventions (e.g., constants all caps), no wildcard imports, etc., are typical. Checkstyle has no concept of “warnings” vs “errors” internally – it’s up to the build config to decide if violations should fail the build. By default, the Maven plugin will just log violations; setting `failsOnViolation` to true will break the build if any are found.

### PMD 
- **Description:** PMD is an extensible multi-language static analyzer (primarily focused on Java, but also supports Apex, XML, etc.). For Java, it catches code issues like possible bugs (empty try blocks, unused local variables), suboptimal code, and enforces best practices. It also includes CPD (Copy-Paste Detector) to find duplicate code.
- **Type:** Open-source.
- **Configuration:** PMD uses XML rule sets to determine what rules to apply. PMD comes with a set of rules divided by categories (e.g., “Performance,” “Security,” “Style”). You can either use the prepackaged rule sets (by referencing them in the config) or create a custom `ruleset.xml` that includes/excludes specific rules. An example `ruleset.xml`:
  ```xml
  <ruleset name="Custom Rules"
           xmlns="http://pmd.sourceforge.net/ruleset/2.0.0"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://pmd.sourceforge.net/ruleset/2.0.0
               http://pmd.sourceforge.net/ruleset_2_0_0.xsd"
           >
    <description>My custom PMD rules</description>
    <rule ref="category/java/bestpractices.xml/UnusedLocalVariable"/>
    <rule ref="category/java/errorprone.xml"/>
    <rule ref="category/java/design.xml/TooManyFields">
      <properties>
        <property name="threshold" value="20"/>
      </properties>
    </rule>
    <!-- ... -->
  </ruleset>
  ```
  This example includes all rules from *errorprone* category and specific rules from others, with a property override. The configuration flexibility is high. If not configured, one might use PMD’s default rule set, but usually projects maintain their own selection.
- **CI/Build Integration:** Like Checkstyle, often integrated via build tools. Maven’s PMD plugin or Gradle’s PMD plugin can run checks. Example Maven plugin config:
  ```xml
  <plugin>
    <artifactId>maven-pmd-plugin</artifactId>
    <version>3.15.0</version>
    <configuration>
      <rulesetFiles>config/pmd/ruleset.xml</rulesetFiles>
      <failOnViolation>true</failOnViolation>
    </configuration>
  </plugin>
  ```
  Running `mvn pmd:check` will then fail if violations are found. For Gradle, apply the `pmd` plugin and configure `pmd.rulesetFile`. In CI, ensure the analysis runs and possibly produce the PMD report (usually an XML at `target/pmd.xml`).
- **CPD (Copy Paste Detector):** PMD’s suite includes CPD which can be run separately to detect duplicated code segments. This can also be part of CI to discourage large copy-pasted blocks.

### SpotBugs (FindBugs) 
- **Description:** SpotBugs is the successor of the FindBugs project. It analyzes Java bytecode to find bug patterns (null pointer dereferences, infinite loops, bad uses of APIs, etc.). It’s more bug-focused (semantic analysis) than style-focused.
- **Type:** Open-source.
- **Configuration:** SpotBugs can be run with default detectors or a custom filter to exclude certain findings. Typically, configuration involves:
  - **Exclude/Include Filters:** XML files that specify which bug patterns to exclude or include. For example, a `findbugs-exclude.xml` can mark certain classes or bug types to skip (like known false positives). This file uses `<FindBugsFilter>` root with `<Match>` subelements to match bug instances ([Chapter 8. Filter Files - FindBugs](https://findbugs.sourceforge.net/manual/filter.html#:~:text=A%20filter%20file%20is%20an,exclude%20myExcludeFilter.xml%20myApp.jar)). For example:
    ```xml
    <FindBugsFilter>
      <Match>
        <Bug code="DMI" />            <!-- exclude all Dodgy Code warnings -->
      </Match>
      <Match>
        <Class name="~.*Generated.*" />  <!-- exclude classes with Generated in name -->
      </Match>
    </FindBugsFilter>
    ```
  - **Effort and Threshold:** SpotBugs allows tuning “effort” (analysis depth) and a threshold for reporting (e.g., only medium+ confidence bugs).
  Otherwise, you typically don’t need a config file in the repo except the optional exclude/include filters.
- **CI/Build Integration:** SpotBugs has a Maven plugin (formerly FindBugs plugin) and a Gradle plugin. In Maven:
  ```xml
  <plugin>
    <groupId>com.github.spotbugs</groupId>
    <artifactId>spotbugs-maven-plugin</artifactId>
    <version>4.7.3.0</version>
    <configuration>
      <excludeFilterFile>findbugs-exclude.xml</excludeFilterFile>
      <failOnError>false</failOnError>
    </configuration>
    <executions> ... </executions>
  </plugin>
  ```
  This runs SpotBugs. Usually, teams set it to not fail the build automatically but rather generate a report for review (unless they have a policy to treat certain bug types as build-breakers). In Gradle, the `spotbugs` plugin can generate reports (and you can configure `ignoreFailures` and the path to an exclude filter).
- **Output:** SpotBugs results include bug type categories like “NP_NULL_ON_SOME_PATH” (possible null pointer), “URF_UNREAD_FIELD” (field never read), etc. The config can map these to priorities or filter them. There’s also a GUI (SpotBugs GUI) that can load results and help create an exclude filter by selecting false positives ([How do I convert findbugsXml.xml to an excludeFilterFile? #72 - GitHub](https://github.com/spotbugs/discuss/issues/72#:~:text=According%20to%20this%20Stack%20Overflow,file%20with%20the%20following%20content)).
- **Note:** FindBugs/SpotBugs also has an extension called **FindSecurityBugs** (or SpotBugs plugin for security) that adds security-related bug patterns (SQL injection, etc.) primarily for Java web apps. If used, it might have its own configuration or rule selection, but mostly it’s plug-and-play.

### Error Prone 
- **Description:** Error Prone is a static analysis tool from Google that catches common Java mistakes at compile time. It acts as a replacement for the Java compiler (Javac) step, integrating error checks.
- **Type:** Open-source (as a compiler plugin).
- **Configuration:** Configured via compiler flags or annotations. It comes with a set of built-in bug checkers (e.g., identifying uses of `==` on strings, misplaced null checks, etc.). You can disable or enable specific checks via command-line options (`-Xep:disable CheckName` or `-Xep:CheckName:ERROR` to elevate severity). Some projects include an `errorprone.xml` to list disabled checks, but the typical approach is flags in the build config. For example, in Maven or Bazel, one might pass `-Xep:BanForbiddenAPIs:WARN` to adjust the severity of a rule. Also, you can suppress a finding in code with the `@SuppressWarnings("CheckName")` annotation for false positives or intentional deviations.
- **CI Integration:** Often integrated by replacing the normal `javac` with Error Prone’s javac. In Maven, using the Error Prone compiler plugin or in Gradle with the ErrorProne Gradle plugin. When integrated, any triggered error will fail the compilation (if at ERROR level). Teams use it to prevent bug patterns from ever entering the codebase. Running this in CI is just part of compilation – no separate stage needed. If not integrated, one could run it as an annotation processor step.

### FB Infer 
- **Description:** Infer (Facebook Infer) is a static analysis tool originally by Facebook, geared towards detecting memory and concurrency issues in C/C++ and Java (it also supports Objective-C). For Java, it finds issues like null dereferences, resource leaks, etc.
- **Type:** Open-source.
- **Configuration:** Infer is run as a separate tool that intercepts the build. You typically don’t put config in the codebase; instead, run `infer -- mvn compile` or similar. It does allow certain filters or option flags (like specifying which detectors to run). You can also mark false positives in code with `@SuppressWarnings("infer")` for some issue types.
- **CI Integration:** If a project uses Infer, you’d integrate by invoking the infer analysis in CI. For example:
  ```yaml
  static_analysis:
    image: facebookinfer/infer:latest
    script:
      - infer run -- gradle build
  ```
  After running, Infer produces a report of issues. If you want to fail CI on any found issue, you’d parse the results or use Infer’s exit status (Infer can return non-zero if issues of certain severity are found). Typically, Infer is more common in native mobile (C/C++/Obj-C) or where memory issues are a concern, but it can be applied to Java code too.

### Others (Java)
- **Lint for Android:** The Android SDK has a built-in static analysis (Android Lint) which checks Android-specific best practices (and some general Java/Kotlin issues). It’s configured via an `lint.xml` file for custom severity of checks. This runs automatically in Android Studio or via Gradle (`./gradlew lint`). It’s important for Android projects to catch issues like missing translations or inefficient layouts.
- **ArchUnit:** A testing library (not exactly a standalone tool) that allows you to write unit tests for architectural constraints (like “all service classes should reside in ..service.. package”). It’s a form of static analysis enforced via tests.
- **FindBugs (historic):** Predecessor to SpotBugs, now discontinued. 
- **SAST Tools:** Many of the multi-language SAST tools (SonarQube, Fortify, Checkmarx, Veracode, etc.) heavily support Java and are used in enterprise Java projects for security scanning beyond what the above open-source tools do.

Java projects often use Checkstyle + PMD + SpotBugs together (each catching different things), sometimes integrated into one Maven **site** report or CI step. This provides broad coverage: Checkstyle for style/conventions, PMD for code issues, SpotBugs for potential bugs. Modern trend with code quality in Java also involves using SonarQube which can combine all these aspects and more.

## C/C++ Static Analysis Tools

### Cppcheck 
- **Description:** Cppcheck is an open-source static analyzer for C and C++ that focuses on finding bugs and undefined behavior (memory leaks, out of bounds, use-after-free, etc.), as well as some coding style issues. It aims to be false-positive-suppressive and easy to integrate.
- **Configuration:** Cppcheck can be configured via command-line parameters or an optional configuration file for suppressions. Common usage is to specify include paths (`-I`), enable extra checks (like `--enable=warning,style,performance,portability` to include those categories). If there are specific false positives, one can use inline comments in code `// cppcheck-suppress <CheckName>` or provide a suppressions file (`cppcheckSuppressions.txt`) with patterns of warnings to ignore. No standard config file format exists aside from suppressions. 
- **CI Integration:** Cppcheck has a CLI, so you run something like:
  ```bash
  cppcheck --enable=all --inline-suppr --project=compile_commands.json 2> cppcheck-report.txt
  ```
  This example uses a compile database to know what to check, and writes warnings to a text file. In CI (GitLab), you might use a community Docker image for Cppcheck or install it on the runner. The exit code of Cppcheck is 0 even if it finds issues (it doesn’t fail the build by default), so to make CI fail on issues, you’d need to parse the output or use the `--error-exitcode=` flag to set an exit code on certain message severities. Many teams treat Cppcheck results as informational, unless they integrate it via something like SonarQube or a code quality gate.
- **Note:** Cppcheck can output XML or JSON reports. It also supports MISRA C rules (with a license). It does not require code compilation (works on source), which makes it easy to run at any point.

### Clang-Tidy 
- **Description:** Clang-Tidy is part of the LLVM/Clang tooling. It’s a C++ “linter” that comes with a wide array of checks (readability, modernize, performance, bugprone, etc.) and can also apply automatic fixes for some issues. It’s effectively the go-to static analyzer for C++ alongside compiler warnings.
- **Configuration:** Clang-Tidy is configured via a `.clang-tidy` file (YAML format) in the project or via command-line. The config file can specify which checks to enable or disable (using glob patterns for check names), for example:
  ```yaml
  Checks: >
    clang-analyzer-*,
    modernize-*,
    performance-*,
    -modernize-use-trailing-return-type,
    -clang-analyzer-security.*
  WarningsAsErrors: clang-analyzer-*,bugprone-*
  ```
  This enables all Clang Static Analyzer checks and modernize/performance checks, but disables a specific one and all security analyzer checks, and treats certain groups as errors. If no `.clang-tidy` file is present, you typically pass `-checks=` argument in the CLI.
- **CI Integration:** Clang-Tidy is often run as part of the CMake build or explicitly in CI. If using CMake, you can add CMake targets to run clang-tidy on files (CMake has `CMAKE_CXX_CLANG_TIDY` option to automatically run it during compilation). Otherwise, in CI:
  ```yaml
  lint:clang_tidy:
    image: gcc:11
    script:
      - apt-get update && apt-get install -y clang-tidy
      - clang-tidy --quiet -p build/compile_commands.json $(find src -name "*.cpp")
  ```
  Here, a compile commands database is used so clang-tidy knows include paths and macros. The `find` feeds all source files. Clang-Tidy’s exit code is tricky: by default, it won’t fail even if warnings are found. One method to fail CI is to grep the output for “warning:” or set `-warnings-as-errors=*` (as seen in config above or via `-warnings-as-errors=` flag) to treat all warnings as errors (then clang-tidy returns non-zero). Another approach is to use a wrapper script to count issues. Many treat clang-tidy suggestions as advisory, especially if running a broad set of checks.
- **Auto-fix:** Clang-Tidy can automatically fix certain issues with `-fix` option (like converting `NULL` to `nullptr`, etc.), but that’s not typically used in CI (more in local dev or a separate formatting job).

### Clang Static Analyzer (scan-build) 
- **Description:** The Clang Static Analyzer is a tool that runs as part of Clang’s `scan-build`. It finds bugs by exploring code paths (e.g., null dereferences, uninitialized values, leaks). This is older than clang-tidy and specifically focused on bug finding.
- **Configuration:** Not much config file-wise. You run it via the `scan-build` script which analyzes a build. For example: `scan-build -o scan_report make`. You can specify the output format, and which analyzer checks to use via `-enable-checker` or `-disable-checker` flags. Checkers can be tuned by environment variables or config files if needed, but generally command-line is used.
- **CI Integration:** In CI, you might do:
  ```bash
  scan-build -o scan_results --status-bugs make
  ```
  The `--status-bugs` flag makes `scan-build` return non-zero if it found any bugs, which is useful to fail CI if desired. The analysis results (HTML files) would be in `scan_results` directory; these could be archived. This approach means the code is analyzed while being compiled with Clang (so your project needs to build with Clang for the analyzer to work).
- **Notes:** Nowadays, much of Clang Static Analyzer’s functionality is available as part of Clang-Tidy under the clang-analyzer checks, so one might just use Clang-Tidy. But `scan-build` is still used in some C projects or as part of build pipelines.

### Visual C++ / MSVC Analyzer 
- **Description:** Microsoft’s Visual C++ compiler has static analysis capabilities (enabled with flags like `/analyze`). It finds potential issues in C/C++ code (buffer overruns, use-after-free, etc.), similar to what Clang analyzer does.
- **Configuration:** Controlled by compiler flags and optional annotations (SAL annotations in code). For example, running MSVC with `/analyze:ruleset` allows specifying a ruleset file to enforce particular rules (the ruleset is an XML `.ruleset` file, similar to those used in .NET, but for native code analysis).
- **CI Integration:** On Windows, you might compile with `/analyze` and treat warnings as errors for certain code analysis warnings. Azure DevOps or other pipelines can ingest these warnings. This is mostly relevant in a Windows ecosystem and not via `.gitlab-ci.yml` unless using Windows runners.

### PVS-Studio 
- **Description:** PVS-Studio is a commercial static analyzer for C, C++ (and also C#, Java). It’s known for catching a wide range of bugs and potential issues (somewhat like a super-powerful combination of all the above). It’s proprietary.
- **Configuration:** PVS-Studio uses configuration files (PVS-Studio.cfg) or command-line to control which diagnostics to enable. Developers can also suppress warnings via comments (`//-V112` to suppress a particular warning in code) or an external suppress file. PVS-Studio has levels of warnings (1-4) and categories (General, OPT, 64-bit, MISRA, etc.). Config involves choosing those and specifying include/exclude paths.
- **CI Integration:** Often run via its compiler monitoring or CMake integration. For CI, PVS provides a command-line tool that either hooks into builds or analyzes a compile database. Example integration:
  - Use `pvs-studio-analyzer` to intercept the build and create a log of compilation.
  - Then run `pvs-studio-analyzer analyze` to produce a report (like `report.plog`).
  - Convert the report to human-readable form with `plog-converter` (to text, HTML, or even SonarQube format).
  In `.gitlab-ci.yml`, if you have the PVS-Studio tools available (requires licensing), you can script these steps. PVS-Studio also has a free option for open-source projects (requires adding a special comment in your code base as a watermark).
- **Note:** Because it’s commercial, config details are usually in their documentation. Many teams run PVS-Studio periodically or on a separate track due to license limits, rather than every push (unless they have enterprise licenses).

### CppLint 
- **Description:** CppLint is a style linter for C++ (created by Google, for enforcing Google’s C++ style guide) ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=comparing%20different%20versions%20of%20the,%E2%80%94%20%20%2092%20Abstract)). It’s much simpler and only style-related compared to the above bug-finding tools.
- **Configuration:** Config via command-line flags or a configuration at top of files (special comments for NOLINT). Example usage: `cpplint --filter=-whitespace/braces --linelength=100 *.cpp`. It’s not commonly used outside of Google-related projects; clang-format has taken over for style issues and other tools for actual static analysis.
- **CI Integration:** Just run `cpplint` on the files; it will output style violations and exit non-zero if any issues (depending on severity filtering).

### Other C/C++ Tools
- **MISRA and Safety Checkers:** Tools like LDRA, QA-C/QA-C++ (Helix QAC) ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=processes%20and%20systems,%E2%80%94%20%20%E2%80%94%20%20%E2%80%94)), GrammaTech CodeSonar ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=monitoring,Runtime%20Library%20Exception%20%20%E2%80%94)), and others are used in industries for compliance (MISRA, ISO 26262) and deep static analysis. These are commercial and have their own configuration systems (usually via their GUIs or config files).
- **Splint:** An older open-source analyzer for C (no C++), primarily for speculatively checking annotations. Not widely used now.
- **Frama-C:** Advanced static analysis framework for C, with specification capabilities (mostly in academic or specialized use) ([List of tools for static code analysis - Wikipedia](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis#:~:text=Frama,interpretation%2C%20deductive%20verification%20and%20runtime)).
- **clang-format:** (Not analysis, but formatting) – often paired with static analysis to ensure code style uniformity, config via `.clang-format`.
- **Sanitizers (ASan, UBSan, etc.):** Though dynamic, they often complement static analysis by catching issues at runtime tests.

Typically, C/C++ projects will use a mix of compiler warnings (with `-Wall -Wextra -Werror` for GCC/Clang or `/W4 /WX` for MSVC), plus one or more static analysis tools like Cppcheck (fast, easy) or Clang-Tidy for deeper issues and modernization suggestions. High-integrity projects might add PVS-Studio or Coverity for even more thorough analysis.

## C# / .NET Static Analysis Tools

### .NET Roslyn Analyzers (FxCop Analyzers) 
- **Description:** Modern .NET (C# and VB.NET) has static code analysis via Roslyn analyzers. These are NuGet packages (Microsoft.CodeAnalysis.FxCopAnalyzers, or now part of .NET SDK) that provide rules similar to the old FxCop. They run during build and flag code issues, design rule violations, etc.
- **Configuration:** In .NET, you typically configure these via an **EditorConfig** file. An `.editorconfig` can set rule severities for analyzers:
  ```ini
  dotnet_analyzer_diagnostic.category-Performance.severity = warning
  dotnet_diagnostic.CA2000.severity = error    # for example, make "Dispose objects before losing scope" an error
  ```
  The SDK comes with a default ruleset for CA (CodeAnalysis) rules, and you can adjust each rule’s severity or suppression in EditorConfig. Older approach: a `.ruleset` XML file could be used in project files to configure rules (this is legacy but still supported). Additionally, specific analyzers (e.g., StyleCopAnalyzers) might use their own config files or also rely on EditorConfig.
- **Usage:** When you build a .NET project (via `msbuild` or `dotnet build`), the analyzers run and output warnings or errors. To fail the build on warnings, you can use `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` or set specific rules to error severity as shown.
- **CI Integration:** No special step needed if included in the build. Just ensure your project references the analyzer packages and that warnings-as-errors is set appropriately. The output will show any violations as build errors. For legacy FxCop (post-build analysis of assemblies), the approach was to run the FxCopCmd tool with an FxCop project config, but that’s largely superseded by Roslyn analyzers.
- **Example rules:** CA1822 (mark members static if possible), CA2000 (dispose objects), CA1805 (unused locals), etc., and many naming/design rules. All can be managed in EditorConfig now, which is great for keeping config in version control.

### StyleCop (Analyzers) 
- **Description:** StyleCop was a static analysis tool focusing on C# style and consistency (originally it analyzed source for naming conventions, spacing, etc.). The modern incarnation is **StyleCop Analyzers** as a Roslyn analyzer package.
- **Configuration:** StyleCop Analyzers can use an `stylecop.json` file to configure certain style rules (for example, rules about file naming, using directives ordering). EditorConfig can also configure many of these now. If using `stylecop.json`, you place it in the project directory, and it might include settings like:
  ```json
  {
    "settings": {
      "documentationRules": {
        "companyName": "MyCompany",
        "copyrightText": "Copyright (c) 2023"
      }
    }
  }
  ```
  Most StyleCop rules are about code style (SAxxxx rule IDs).
- **CI Integration:** Also via build since it’s a Roslyn analyzer package (if you include it). It will produce warnings (or errors if configured) during compilation. Ensure the build fails on violations if desired by treating warnings as errors or adjusting severities in EditorConfig.
- **Note:** Many teams prefer EditorConfig now for all style settings (which also covers formatting rules for IDE/editor), and use an auto-formatter (dotnet format or IDE) for style. StyleCop Analyzers is optional, used if teams want to enforce certain old StyleCop conventions.

### ReSharper Command-Line Tools (InspectCode) 
- **Description:** ReSharper (a JetBrains IDE plugin for Visual Studio) has a set of code inspections for .NET. JetBrains provides a command-line tool called **InspectCode** that can run these inspections outside of Visual Studio.
- **Type:** Commercial (free for open source).
- **Configuration:** It can use ReSharper’s settings files (`.DotSettings` files) to configure which inspections are enabled or their severity. Typically, a team might configure inspections via ReSharper in the IDE and share a DotSettings file, which InspectCode will respect. Alternatively, pass command-line arguments to disable certain inspection categories.
- **CI Integration:** Use the JetBrains provided CLI (InspectCode.exe for Windows, or a cross-platform Rider-based tool). Example:
  ```yaml
  inspectcode:
    image: jetbrains/resharper-cli:latest
    script:
      - InspectCode ./MySolution.sln /output=Report.xml /profile=Debug
  ```
  This runs code analysis and produces an XML report of issues. You’d then analyze that or fail the build based on certain findings. Since this is an external tool, it won’t fail CI unless you script logic to parse the report and decide to fail on specific issues (JetBrains provides some severity levels that you can filter).
- **Benefit:** It includes many coding best practice suggestions and can find issues similar to MS analyzers, sometimes more. But if using Roslyn analyzers fully, InspectCode may overlap. Some projects use it to complement or to get ReSharper-specific insights in CI.

### NDepend 
- **Description:** NDepend is a commercial static analysis tool for .NET that focuses on code quality metrics, architecture, and complex queries (via its own LINQ-like query language for code, CQLinq). It finds things like overly complex methods, dependency cycles, etc., and gives a maintainability rating.
- **Configuration:** Configured via an NDepend project file (`*.ndproj`) which includes which rules (queries) to run, thresholds for metrics, etc. NDepend comes with default rule sets, all expressed as CQLinq queries you can customize or write new ones. For example, a rule might be: “Methods with Cyclomatic Complexity > 20” as a query, which NDepend will evaluate.
- **CI Integration:** NDepend can be run with its console tool (`NDepend.Console.exe`) given an ndproj config. It will output an HTML or XML report and return a non-zero exit code if there are rule violations marked as breaking. So you can incorporate that into CI, failing if NDepend flags too many issues or violates some quality gate. This is typically used in enterprise scenarios focusing on long-term code health.
- **Note:** NDepend’s results are often used in reports rather than failing each build unless the team sets strict thresholds (like no new dependency cycles or no method above X complexity).

### Security Linters and Scanners for .NET 
- **FxCop rules for security:** Roslyn analyzers include some security rules (like CA2100 for SQL injection checks on ADO.NET usage).
- **DevSkim:** Analyzers by Microsoft that look for security issues in code (e.g., banned APIs). Config via JSON.
- **Roslyn Security Guard:** An older project for security analyzers (not heavily maintained now).
- **Static analyzers in enterprise:** Fortify, Veracode, etc., all support scanning .NET code (including analyzing compiled binaries for patterns). Those were covered in multi-language section.

In summary, .NET developers rely on the built-in Roslyn analyzers for general issues (which come as part of the .NET SDK now, e.g., .NET 5+ includes many rules by default) and may add specific ones (StyleCop, third-party analyzers). Configuration is mainly centralized in **.editorconfig** files in modern .NET projects for all these analyzers, making it straightforward to tweak rule severities project-wide.

## Ruby Static Analysis Tools

### RuboCop 
- **Description:** RuboCop is the standard linter/formatter for Ruby. It enforces the Ruby Style Guide and also flags potential errors or code smells. RuboCop can automatically correct many issues as well.
- **Type:** Open-source.
- **Configuration:** RuboCop is configured via a `.rubocop.yml` file in the project root. This YAML config can enable/disable certain cops (rules) or customize their parameters. For example:
  ```yaml
  AllCops:
    TargetRubyVersion: 3.0
    Exclude:
      - db/schema.rb
  Layout/LineLength:
    Max: 100
  Metrics/MethodLength:
    Max: 15
    Exclude:
      - 'lib/tasks/**/*.rake'
  Style/StringLiterals:
    EnforcedStyle: single_quotes
  ```
  This sets the Ruby version, excludes some files, sets line length to 100, method length to 15 lines (with an exclusion), and enforces single quotes for string literals. If no `.rubocop.yml` is present, RuboCop uses a default config (based on the Ruby Style Guide) ([Configuration - RuboCop Docs](https://docs.rubocop.org/rubocop/configuration.html#:~:text=The%20file%20config%2Fdefault,yml%20will%20be%20used)) ([Basic Usage - RuboCop Docs](https://docs.rubocop.org/rubocop/usage/basic_usage.html#:~:text=Basic%20Usage%20,config)). You can inherit from the default or other shared configs by using the `inherit_from:` key (for example, many use `inherit_gem: rubocop-rails` for Rails-specific rules).
- **CI Integration:** Running RuboCop in CI is straightforward. In a Ruby environment, simply execute `rubocop`. If any offenses are detected and not auto-corrected, RuboCop exits with code 1, failing the job. A GitLab CI job example:
  ```yaml
  lint:ruby:
    image: ruby:3.1
    script:
      - gem install rubocop
      - rubocop
  ```
  Optionally add `-P` (display cop names) or `-a` (auto-correct, though you typically wouldn’t auto-correct in CI). Many projects treat RuboCop offenses as build failures to ensure style consistency and basic code health.
- **Pre-commit Integration:** One can use pre-commit framework or Overcommit (a Ruby gem for managing git hooks) to run RuboCop on changed files pre-commit. In `.pre-commit-config.yaml`:
  ```yaml
  - repo: https://github.com/pre-commit/mirrors-rubocop
    rev: v1.50.2
    hooks:
      - id: rubocop
  ```
  This mirror runs RuboCop (requires Ruby available).

### Brakeman 
- **Description:** Brakeman is a static analysis security scanner for Ruby on Rails applications. It looks for vulnerabilities like SQL injection, XSS, unsafe deserialization, etc., in Rails code (and some general Ruby patterns).
- **Type:** Open-source.
- **Configuration:** Brakeman can run with zero config for a Rails app (it auto-detects routes, templates, etc.). Configuration is mainly for ignoring warnings or adjusting thresholds:
  - **Ignore Config:** Brakeman uses an “ignore file” (`brakeman.ignore`) to suppress specific warnings (often false positives). This is a YAML or JSON where you list warnings (by fingerprint) to ignore. Brakeman can generate this interactively (`brakeman -I`) ([Brakeman: Ignoring False Positives](https://brakemanscanner.org/docs/ignoring_false_positives/#:~:text=This%20functionality%20was%20introduced%20in,existing%20configuration%20file%20to%20load)) ([brakeman - Security Cipher](https://securitycipher.com/links/all/brakeman/#:~:text=brakeman%20,ignored)).
  - **Configuration File:** Brakeman options (like which checks to run) can be stored in a YAML file and passed with `--config`. But typically not needed; defaults are fine.
- **CI Integration:** Running `brakeman` on a Rails project will output a report and exit with 0 even if it finds warnings (it does not fail the build by default). You can add `--exit-on-warn` flag to make it exit non-zero if any warnings are found, which is useful for CI gating ([Automatic Security Testing of Rails Applications Using Brakeman](https://semaphoreci.com/community/tutorials/automatic-security-testing-of-rails-applications-using-brakeman#:~:text=Brakeman%20semaphoreci,warnings%20won%E2%80%99t%20be%20reported%20again)). For example:
  ```yaml
  security_scan:
    image: ruby:3.0
    script:
      - gem install brakeman
      - brakeman --quiet --exit-on-warn
  ```
  This will fail the job if Brakeman reports any warnings (except those ignored via `brakeman.ignore`). The `--format` option can produce JSON or HTML reports if needed as artifacts.
- **Keeping Track:** Teams often maintain the `config/brakeman.ignore` file with fingerprints of known safe warnings ([GitHub - presidentbeef/brakeman: A static analysis security ...](https://github.com/presidentbeef/brakeman#:~:text=GitHub%20,the%20warnings%20you%20ignored%20without)), and update it as code changes (fingerprints will change if the code around the warning changes). The ignore file ensures Brakeman only fails the build for new or unreviewed issues.
- **Note:** Brakeman is specific to Rails; for general Ruby security analysis outside of Rails, one might use simpler grep-based tools or bundler-audit for gem vulnerabilities. But Brakeman is a must for Rails security-conscious development.

### Reek 
- **Description:** Reek is a tool that sniffs out “code smells” in Ruby – e.g., methods that are too long, classes that might be doing too much, etc.
- **Configuration:** Config via a `.reek.yml`. You can enable/disable specific smells and set thresholds. Example:
  ```yaml
  DetectDuplicateMethodCall:
    enabled: true
    allow_calls: [ { name: puts, max_calls: 2 } ]
  IrresponsibleModule:
    enabled: false
  ```
  If not configured, Reek has default smell detectors. It’s often used ad-hoc to identify refactoring opportunities.
- **Integration:** Could run in CI along with RuboCop, but failing a build on Reek smells is less common (since some smells are subjective). Usually used in analysis mode.

### Others (Ruby)
- **flog** – calculates complexity score of methods.
- **flay** – detects structural code duplication.
- **Ruby Type Checkers** – (experimental) Sorbet or RBS with type signature checking, not mainstream in CI yet for most.
- **Security** – besides Brakeman, tools like Bundler-Audit (checks for vulnerable gem versions via advisory DB) are used in CI (config via a `Gemfile.lock` audit, no special file needed). Also, Synk or Gemnasium (now integrated into GitLab) for dependency scanning.

Ruby projects typically use RuboCop as a baseline linter. Rails projects add Brakeman for security. Others like Reek/flay are less frequently gating CI; they might be run for informational output.

## PHP Static Analysis Tools

### PHP_CodeSniffer (PHPCS) 
- **Description:** PHP_CodeSniffer is a tool that checks PHP code for style conformance and some types of bugs. It includes the PSR-1 and PSR-2 (now PSR-12) coding standard definitions and allows custom standards.
- **Type:** Open-source.
- **Configuration:** Configured by specifying a “standard.” This could be one of the built-ins (PSR12, PEAR, etc.) or a custom ruleset XML. A custom `ruleset.xml` is similar to Checkstyle/PMD’s in concept. For example:
  ```xml
  <?xml version="1.0"?>
  <ruleset name="CustomStandard">
    <description>My coding standard.</description>
    <rule ref="PSR12"/>
    <!-- Disable a specific rule -->
    <rule ref="Squiz.Functions.GlobalFunction">
      <exclude name="Squiz.Functions.GlobalFunction.Found"/>
    </rule>
    <!-- Change severity of a rule -->
    <rule ref="Generic.PHP.NoEcho">
      <severity>5</severity>
    </rule>
  </ruleset>
  ```
  If using a custom ruleset, it’s common to put `ruleset.xml` in the project root. You can also set some config in a `phpcs.xml` (which CodeSniffer will auto-detect) to define your standard and file exclusions. Another simpler way: some projects just note the standard in README and not commit a config if using a known standard.
- **CI Integration:** After requiring `squizlabs/php_codesniffer` (the package), run `phpcs --standard=ruleset.xml src/`. If any errors are found (violations), `phpcs` exits with a non-zero code, failing the job. In GitLab CI:
  ```yaml
  phpcs:
    image: php:8.1
    script:
      - pecl install xdebug && docker-php-ext-enable xdebug # (if needed for rules that require it)
      - composer install
      - ./vendor/bin/phpcs --standard=phpcs.xml
  ```
  where `phpcs.xml` is your config file. You might use a community Docker image to avoid installing composer packages manually. PHPCS also has an auto-fixer companion, PHPCBF (Code Beautifier and Fixer), to auto-fix style issues (which could be run locally or as a separate CI job).
- **Standards:** There are many community standards (like WordPress, Zend, Drupal). You can include those via additional packages and reference them in your ruleset.

### PHPMD (PHP Mess Detector) 
- **Description:** PHPMD is based on the PMD project but for PHP. It looks for possible bugs, suboptimal code, and overcomplicated expressions (e.g., unused parameters, excessively long methods, overly complex expressions).
- **Type:** Open-source.
- **Configuration:** Like PMD, configured via an XML ruleset. PHPMD has predefined rule sets (cleancode, codesize, controversial, design, naming, unusedcode). You can run with those or create custom sets. Example usage: `phpmd src/ text phpmd-ruleset.xml`. A ruleset example might disable some rules or set a threshold:
  ```xml
  <ruleset name="Custom PHPMD Rules" 
           xmlns="http://pmd.sf.net/ruleset/2.0.0/php" 
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://pmd.sf.net/ruleset/2.0.0/php 
                               http://pmd.sf.net/ruleset-2.0.0.xsd">
    <description>My rules</description>
    <exclude name="UnusedFormalParameter"/>
    <rule ref="cleancode.xml/BooleanArgumentFlag"/>
    <rule ref="codesize.xml/ExcessiveMethodLength">
       <properties>
          <property name="minimum" value="50"/>
       </properties>
    </rule>
  </ruleset>
  ```
  If no custom ruleset is passed, you must specify which of the built-in sets to run.
- **CI Integration:** Similar to PHPCS, after installing PHPMD (usually via Composer), run it in CI. It will exit with code 0 even if issues found (it just prints them). If you want CI to fail on any findings, you might need to process the output or see if PHPMD has a flag to change exit code behavior (it doesn’t by default). A simple approach is to run PHPMD in a script and then fail if the output contains “Violation”. Alternatively, many incorporate PHPMD into a build tool (like a PHPUnit test that fails if PHPMD count > 0, or use GitLab Code Quality artifact format).
- **Usage:** PHPMD is good for catching things like dead code or long method warnings. It complements PHPCS (style) by focusing more on code quality.

### PHPStan 
- **Description:** PHPStan is a static analysis tool that focuses on finding logical errors in PHP code by doing data flow analysis and type inference. It requires PHP code to be written with certain level of types/hints to be most effective (or you gradually increase its strictness).
- **Type:** Open-source.
- **Configuration:** PHPStan is configured via a `phpstan.neon` (or `phpstan.neon.dist`) file in the project. In it, you set the analysis level (0 to 9, where 9 is strictest), paths to analyze, and include any extension configurations (for frameworks, etc.). Example `phpstan.neon`:
  ```yaml
  parameters:
    level: 5
    paths:
      - src/
      - tests/
    ignoreErrors:
      - '#Undefined variable: \$\w+#'   # regex to ignore certain error patterns
    excludePaths:
      - tests/temp/*
    bootstrapFiles:
      - phpstan-bootstrap.php
  ```
  There are many rules and extensions (for example, to teach PHPStan about Laravel or WordPress internal magic). The level controls how strict (higher levels catch more subtle issues but may require more type annotations).
- **CI Integration:** Install via Composer and run `phpstan analyse`. If it finds errors, it exits with 1, failing the job. Common in CI:
  ```yaml
  phpstan:
    image: php:8.2
    script:
      - composer install
      - vendor/bin/phpstan analyse
  ```
  Possibly split by paths or run with memory limit options if needed (PHPStan can be memory heavy on large codebases). Typically, projects aim to keep PHPStan at a certain level with 0 errors. The ignoreErrors section can filter out known false positives or issues that are acceptable.
- **Note:** PHPStan is quite powerful for catching mistakes like calling undefined methods, wrong types passed to functions, etc., which would otherwise only show up at runtime. It’s akin to MyPy for Python or JSLint vs TypeScript.

### Psalm 
- **Description:** Psalm is another static analysis tool for PHP, with a focus on strict typing and even providing a type system that can augment plain PHP Docblocks. It’s similar in scope to PHPStan (and there’s a bit of rivalry, with each having slightly different strengths).
- **Type:** Open-source.
- **Configuration:** Config file typically `psalm.xml`. You generate one with `psalm --init`. It’s an XML that lists which directories to scan, which level (Psalm has error levels 1 (strictest) to 8 (loosest), opposite numbering of PHPStan), and issues to ignore or baseline. Example snippet:
  ```xml
  <psalm errorLevel="3">
    <projectFiles>
      <directory name="src" />
      <ignoreFiles>
        <directory name="src/Legacy" />
      </ignoreFiles>
    </projectFiles>
    <issueHandlers>
      <MissingParamType errorLevel="info" />
      <UndefinedGlobalVariable errorLevel="error" />
    </issueHandlers>
  </psalm>
  ```
  Psalm also supports a baseline file (`psalm.baseline.xml`) which records all current issues so you can suppress them and work on new issues (useful when introducing into a large legacy project).
- **CI Integration:** After installing, run `psalm` (it will use psalm.xml). Non-zero exit if issues above the configured level are found. Just like PHPStan:
  ```yaml
  psalm:
    image: php:8.1
    script:
      - composer install
      - vendor/bin/psalm --shepherd --stats
  ```
  (The flags here might send data to Psalm’s dashboard and show stats; basic usage is just `psalm`.)
- **Comparison:** Many projects choose either PHPStan or Psalm (some even use both). They cover similar ground. Psalm tends to integrate with certain IDE feedback loops and can be a tad more strict on generics and arrays. Config differences aside, CI usage is essentially the same.

### Other PHP tools
- **PHP-CS-Fixer:** A code style fixer similar to PHPCBF but with more customizable rules. Config via `.php-cs-fixer.php` (a PHP file returning config).
- **Deptrac:** A tool to enforce architectural layer boundaries in PHP. Config via a depfile YAML (specifies layers and allowed dependencies).
- **Phan:** Another static analyzer for PHP (earlier than PHPStan/Psalm, uses AST and has its own strengths, but PHPStan/Psalm are more popular now).
- **Security:** Besides the commercial SAST tools, one might use **ProgPilot** or **RIPS** (an old open source scanner, now commercial as SonarPHP or others) for security scanning. These have configs for sinks/sources or just run with defaults.

Generally, modern PHP projects incorporate CodeSniffer (for standards) and PHPStan/Psalm (for bug detection via types). These significantly improve code quality when used at strict settings.

## Go (Golang) Static Analysis Tools

### GolangCI-Lint 
- **Description:** GolangCI-Lint is a popular meta-linter for Go. It aggregates many Go linters (staticcheck, gofmt, govet, gosec, errcheck, etc.) into one tool and runs them in parallel, making it a one-stop solution for Go code analysis.
- **Type:** Open-source.
- **Configuration:** Configured via a `.golangci.yml` (or .yaml) file in the repository. You can also use `golangci-lint --config path` to specify a config. The config allows selecting which linters to run, setting specific linter options, and excluding certain issues or files. Example `.golangci.yml`:
  ```yaml
  linters:
    enable:
      - govet
      - staticcheck
      - errcheck
      - gofmt
      - gosec
    disable:
      - deadcode
  linters-settings:
    gofmt:
      simplify: true
    gosec:
      # Exclude G304 (path provided as taint input) from vendor/
      exclude-rules:
        - id: G304
          path: 'vendor/**/*'
  run:
    issues-exit-code: 1
    timeout: 5m
    skip-dirs:
      - "examples"
  ```
  This enables a selection of linters, configures them, and sets that the tool should exit with code 1 if any issues are found (which is default behavior when issues exist). The reference configuration file lists all possible settings ([Configuration - golangci-lint](https://golangci-lint.run/usage/configuration/#:~:text=You%20can%20configure%20specific%20linters%27,display%20all%20the%20configuration%20options)), and GolangCI-Lint provides an extensive list of linters it can run.
- **CI Integration:** Many projects just download the GolangCI-Lint binary (or use the Docker image `golangci/golangci-lint`) and run it. For instance, a GitLab CI job:
  ```yaml
  lint:go:
    image: golangci/golangci-lint:v1.52.2
    script:
      - golangci-lint run
  ```
  This will auto-detect the config file and use it. If no config, it has a default set of linters. If issues are found, the job will fail (exit code 1). GolangCI-Lint also can output results in formats like GitLab Code Climate format for integration.
- **Pre-commit Integration:** It’s possible to integrate via pre-commit (there is a hook for GolangCI-Lint).
- **Benefits:** Using GolangCI-Lint simplifies running multiple tools like govet (Go’s built-in analyzer), staticcheck (advanced checks), gosimple, unused, structcheck, and security linters in one go. This is the de facto way to enforce Go code quality.

### go vet (and built-in analyses)
- **Description:** `go vet` is a Go tool that checks for suspicious constructs. It’s included in `go` toolchain, focusing on correctness issues (format string mismatches, misuse of `copy()`, etc.).
- **Configuration:** No config file; it runs a set of analyzers. In Go 1.12+, many vet checks run automatically during `go test`.
- **Usage in CI:** Often just running `go vet ./...` is part of the pipeline. If it finds issues, it outputs them and returns a non-zero code (so failing CI).
- **Extended Vet:** The Go team provides many optional vet-style analyzers (e.g., `cmd/vet` and in `golang.org/x/tools/go/analysis`). Tools like GolangCI-Lint already include these, so one might not run `go vet` separately if using GolangCI-Lint (since it includes vet).

### staticcheck 
- **Description:** Staticcheck is a powerful Go static analyzer (part of the `golangci-lint` set, but can run standalone). It’s like an advanced vet, catching issues like unused code, buggy constructs, and suggesting simplifications.
- **Configuration:** As a standalone, staticcheck can be configured via a JSON or TOML file (recent versions support a config file to enable/disable checks or ignore specific problems). Without config, it runs all checks.
- **Usage:** Running `staticcheck ./...` in CI will yield a non-zero exit if issues found. Most use it through GolangCI-Lint. If using separately, you might configure via a `staticcheck.conf` to, say, ignore certain directories or issues.

### gofmt / goimports 
- **Description:** `gofmt` is the code formatter for Go (enforces a standard format). `goimports` is similar but also manages import statements grouping.
- **Usage:** Often, CI will include a check that code is formatted. e.g., `gofmt -s -d .` which will diff any unformatted code. If the diff is non-empty, the job fails. GolangCI-Lint’s `gofmt` check can handle this as well.

### gosec (Gas) 
- **Description:** gosec (formerly “Gas”) scans Go code for security issues (like hardcoded credentials, `unsafe` usage, SQL injection).
- **Configuration:** Config via a JSON file if needed to include/exclude rules. Otherwise flags like `-exclude=G304,G107` to skip certain rules can be used.
- **Usage:** Usually integrated via GolangCI-Lint (which calls gosec). If standalone: `gosec -severity medium -confidence medium -quiet ./...` and check its exit code. It defaults to exit 0 even if issues found (so might need `-fmt=json` and then parse or use golangci-lint’s exit-on-issues logic).
- **Pre-commit/other integration:** Could run as separate step, but commonly done in one pass with others.

### Others (Go)
- **errcheck:** Checks that you checked errors from functions that return error. (Again, in golangci-lint).
- **ineffassign:** Finds ineffectual assignments (assigned value never used).
- **cyclop:** Measures function complexity (to keep it under e.g. 10).
- **godot/gocritic, etc.:** There are a bunch of smaller linters each with a focus.
- **Security/dependency:** `go mod tidy` and scanning go.sum for vulns via `govulncheck` (or older `go list -m -u all` plus a service). But static analysis wise, not config-file heavy.

Because GolangCI-Lint combines all, typically one **golangci.yml** handles configuration for most of them in one place ([Configuring golangci-lint | GoLand Documentation - JetBrains](https://www.jetbrains.com/help/go/configuring-golangci-lint-in-the-go-linter-plugin.html#:~:text=Configuring%20golangci,if%20your%20project%20builds%20successfully)). For instance, in that config you could set `run:
issues-exit-code: 1` (which it is by default). The file might be committed so that all devs and CI use the same standards.

## Rust Static Analysis Tools

### Clippy 
- **Description:** Clippy is the Rust linter (as part of Rust toolchain). It provides additional warnings (“lints”) beyond the Rust compiler’s built-in checks, focusing on common mistakes and idiomatic improvements.
- **Type:** Open-source (comes with rustc components).
- **Configuration:** Clippy lints can be allowed or denied either in code or via a config in `Cargo.toml`. In Rust 1.51+, you can specify lint levels in the Cargo.toml under `[lint]` or `[package.metadata.clippy]` (but this is not widely used yet). Usually:
  - In code, you use `#[allow(clippy::some_lint)]` or `#[deny(clippy::some_lint)]` at the module or function level.
  - In a project, one might have a top-level lint config by creating a `lib.rs` or `main.rs` with `#![deny(clippy::all)]` or similar to enforce all Clippy lints as errors.
  - You can also use a `clippy.toml` to configure certain lints (like the cognitive complexity threshold) – Clippy will pick it up if present in the working directory. Example `clippy.toml`:
    ```toml
    cognitive-complexity-threshold = 25
    ```
    (Not many lints are configurable though.)
- **Usage:** Run `cargo clippy` to execute Clippy. By default it prints warnings. To fail CI on Clippy warnings, you can use `cargo clippy -- -D warnings` (which will treat all warnings, including Clippy lints, as errors). Or explicitly `-D clippy::all` to deny all Clippy lints.
- **CI Integration:** In a GitLab CI, if Rust is installed:
  ```yaml
  clippy:
    image: rust:1.68
    script:
      - cargo clippy -- -D warnings
  ```
  This will run Clippy and fail on any warning. Clippy uses the same compiler internals, so it needs the code to compile (it will build the project as part of its run).
- **Rustc Warnings:** The Rust compiler itself has many warnings (some lints can be elevated). Projects often include `#![deny(warnings)]` in code to make any compiler warning a build error (this can be overkill, but some do it).
- **Rustfmt:** Not analysis, but the Rust formatter. Typically, `cargo fmt -- --check` in CI to ensure code is formatted (config via `rustfmt.toml` if needed).

### Rust linters beyond Clippy 
Rust doesn’t have as many third-party static analyzers because Clippy and the compiler cover most needs. A few specialized tools:
- **MIR-based const analyzer:** For detecting certain issues, but that’s more experimental.
- **Unsafe code checkers:** There are tools to analyze `unsafe` usage (like `cargo geiger` to count unsafe usage).
- **Security:** Static analysis for Rust security mostly falls to Clippy (which has some lints for usage of `unwrap` etc.) and external audits. Rust’s memory safety by design reduces the need for some categories of analyzers.

## Other/Misc Language Tools

### ShellCheck 
- **Description:** ShellCheck is a widely used static analyzer for shell scripts (bash/sh). It catches issues like syntax errors, undeclared variables, SC2086 (double quote to prevent globbing), etc.
- **Configuration:** No config file by default, but you can disable or enable specific checks via command-line flags or in-script directives. For example, in a script:
  ```bash
  # shellcheck disable=SC2086
  ```
  to disable a specific warning for the next line or file. Excluding paths or tailoring ShellCheck in CI is usually done by selecting what files to run it on (e.g., only `*.sh`).
- **CI Integration:** Use ShellCheck CLI (available via apt or as a Docker `koalaman/shellcheck`). For example:
  ```yaml
  shellcheck:
    image: koalaman/shellcheck-alpine:stable
    script:
      - shellcheck myscript.sh myother.sh
  ```
  If any issues of error level are found, ShellCheck returns non-zero. By default, many ShellCheck findings are just warnings, so you might use `-e` to ignore some or `-s bash` to specify shell dialect.
- **Pre-commit:** ShellCheck has a pre-commit hook too. Or one can integrate with editors.

### Terraform and Cloud Config Linters 
- Tools like `terraform validate` and `tflint` (for Terraform) or `cfn-lint` (for CloudFormation). Config via their own HCL or YAML if needed, usually straightforward.
- **TFLint** uses a `.tflint.hcl` to configure rules.
- These might be relevant if the project contains infrastructure as code.

### SQL Linters 
- Some exist to check SQL queries (for example, in code or migrations) for anti-patterns or style (like `sqlfluff` for SQL formatting/style).
- Likely out of scope unless specifically asked.

### AI/ML and Other Langs 
- For completeness: static analysis exists for many niche languages (like ESLint equivalents for JSON or config files, or special ones like Tekton Lint for Tekton pipeline YAML, etc.). But they are usually not requested unless domain-specific.

----

**Conclusion:** Incorporating static analysis tools into your development workflow, with proper configuration files (like those shown above), helps maintain code quality and catch errors early. The structured configuration — whether it’s a `.eslintrc.json` for a JavaScript project, a `pylintrc` for Python, `.pre-commit-config.yaml` to tie tools together, or language-specific XML/YAML config files — allows teams to customize the rules to their needs and consistently enforce standards across CI pipelines ([
                    GitLab : Automatically testing your Python project |
                cylab.be](https://cylab.be/blog/18/gitlab-automatically-testing-your-python-project#:~:text=test%3Apylint%3A%20image%3A%20python%3A3.6%20script%3A%20,classes%3D_socketobject%20%2A.py)) ([Getting started with Gitlab CI/CD: Eslint - DEV Community](https://dev.to/karltaylor/getting-started-with-gitlab-cicd-eslint-1m80#:~:text=,npm%20i%20eslint)). Each tool has its domain of strength, and using a combination (linters for style, static analyzers for bugs, security scanners for vulnerabilities, CI integration for continuous enforcement) yields the best coverage for code quality.

