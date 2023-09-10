import json
import logging
import os
import re
import tempfile
import urllib.parse
import requests
from bs4 import BeautifulSoup
import subprocess
import git
import xml.etree.ElementTree as ET

EXTENSIONS_TO_LANGUAGE = {
    "js": "javascript",
    "ts": "typescript",
    "py": "python",
    "go": "go",
    "rb": "ruby",
    "java": "java",
    "php": "php",
    "c": "c",
    "cpp": "cpp",
    "h": "c",
    "hpp": "cpp",
    "cs": "c#",
    "lua": "lua",
    "swift": "swift",
    "kt": "kotlin",
    "sh": "shell",
    "json": "json",
    "xml": "xml",
    "yml": "yaml",
    "yaml": "yaml",
    "toml": "toml",
    "ini": "ini",
    "md": "markdown",
    "rust": "rust",
    "maven": "maven",
    "txt": "text",
    "Gemfile": "ruby",
    "mod": "go"
}
DEPENDENCIES_TO_FILE = {
    "javascript": "package.json",
    "typescript": "package.json",
    "python": "requirements.txt",
    "go": "go.mod",
    "ruby": "Gemfile",
    "java": "pom.xml",
    "php": "composer.json",
    "maven": "pom.xml",
    "docker": "Dockerfile",
}
SUPPORTED_TYPES_BY_VENDOR = {
    "socket": ["npm"],
    "deps": ["cargo", "go", "maven", "npm", "pypi"],
    "snyk": ["npm", "pypi", "go", "dockerfile"]
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _extract_dependencies_from_package_json(path):
    with open(path, "r") as f:
        package_json = json.load(f)
        dependencies = package_json.get("dependencies", {})
        dev_dependencies = package_json.get("devDependencies", {})
        all_dependencies = []
        for dependency_key, dependency_value in dependencies.items():
            all_dependencies.append({"name": dependency_key, "version": dependency_value.replace("^", "")})
        for dependency_key, dependency_value in dev_dependencies.items():
            all_dependencies.append({"name": dependency_key, "version": dependency_value.replace("^", "")})
        return all_dependencies


def _extract_dependencies_from_requirements_txt(path):
    with open(path, "r") as f:
        requirements = f.readlines()
        requirements = [requirement.strip() for requirement in requirements]
        all_dependencies = []
        for requirement in requirements:
            if requirement.startswith("#") or requirement.startswith("-r") or requirement.startswith("-e") or requirement.startswith("git+") or requirement.startswith("hg+"):
                continue
            name = requirement
            version = ""
            if "==" in requirement:
                name, version = requirement.split("==")
            elif ">=" in requirement:
                name, version = requirement.split(">=")
            elif "<=" in requirement:
                name, version = requirement.split("<=")
            all_dependencies.append({"name": name, "version": version})
        return all_dependencies


def _extract_dependencies_from_go_mod(path):
    pattern = r"(.*)\s+v(\d+\.\d+\.\d+)"
    dependencies = []
    in_require = False
    with open(path, "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith("require"):
            in_require = True
            continue
        if line.startswith(")"):
            in_require = False
            continue
        if not in_require:
            continue
        if match := re.search(pattern, line):
            name = match.groups()[0].strip()
            version = match.groups()[1]
            if not version:
                version = ""
            dependencies.append({"name": name, "version": version})
    return dependencies


def _extract_dependencies_from_gemfile(path):
    with open(path, "r") as f:
        gemfile = f.readlines()
    pattern = r"gem ['\"]([^'\"]+)['\"](?:,\s*['\"]?([^'\"]+)['\"]?)?"
    dependencies = []
    for line in gemfile:
        if match := re.search(pattern, line):
            name = match.groups()[0]
            version = match.groups()[1]
            if not version:
                version = ""
            dependencies.append({"name": name, "version": version})
    return dependencies


def _extract_dependencies_from_pom_xml(path):
    with open(path, "r") as f:
        tree = ET.parse(f)
    root = tree.getroot()

    namespaces = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
    dependencies = []

    for dependency in root.findall(".//mvn:dependencies/mvn:dependency", namespaces=namespaces):
        group_id = dependency.find("mvn:groupId", namespaces=namespaces)
        artifact_id = dependency.find("mvn:artifactId", namespaces=namespaces)
        version = dependency.find("mvn:version", namespaces=namespaces)
        group_id_text = group_id.text if group_id is not None else ""
        artifact_id_text = artifact_id.text if artifact_id is not None else ""
        version_text = version.text if version is not None else ""
        if version_text.startswith("$"):
            version_text = ""
        dependencies.append({"name": f"{group_id_text}/{artifact_id_text}", "version": version_text})
    return dependencies


def _extract_dependencies_from_dockerfile(path):
    with open(path, "r") as f:
        dockerfile = f.readlines()
    from_pattern = r"^FROM\s+([a-zA-Z0-9:.-]+)"
    apt_pattern = r"RUN\s+apt-get\s+install\s+([a-zA-Z0-9\s-]+)"
    yum_pattern = r"RUN\s+yum\s+install\s+-y\s+([a-zA-Z0-9\s-]+)"
    dependencies = []
    for line in dockerfile:
        if match := re.match(from_pattern, line):
            image = match.groups()[0]
            dependencies.append({"name": image, "version": ""})
        elif match := re.match(apt_pattern, line):
            packages = match.groups()[0]
            packages = packages.split(" ")
            dependencies.extend({"name": package, "version": ""} for package in packages)
        elif match := re.match(yum_pattern, line):
            packages = match.groups()[0]
            packages = packages.split(" ")
            dependencies.extend({"name": package, "version": ""} for package in packages)
    return dependencies


def _handle_dependencies_declaration(path, file_type):
    file_name = os.path.basename(path)
    if file_name == "package.json":
        return "npm", _extract_dependencies_from_package_json(path)
    elif file_name == "requirements.txt":
        return "python", _extract_dependencies_from_requirements_txt(path)
    elif file_name == "go.mod":
        return "go", _extract_dependencies_from_go_mod(path)
    elif file_name == "Gemfile":
        return "ruby", _extract_dependencies_from_gemfile(path)
    elif file_name == "pom.xml":
        return "java", _extract_dependencies_from_pom_xml(path)
    elif file_name == "Dockerfile":
        return "docker", _extract_dependencies_from_dockerfile(path)


def normalize_socket_results(results, name, version, verbose=False):
    results = results.get("score")
    if not results:
        return False
    supply_chain_risk = results.get("supplyChainRisk")
    quality_risk = results.get("quality")
    maintenance_risk = results.get("maintenance")
    vulnerability = results.get("vulnerability")
    license_score = results.get("license")
    dep_score = results.get("depscore")
    if not verbose:
        return {
            "name": name,
            "version": version,
            "supply_chain_risk": int(supply_chain_risk.get("score", 0) * 100),
            "depscore": int(dep_score * 100)
        }
    return {
        "name": name,
        "version": version,
        "supply_chain_risk": int(supply_chain_risk.get("score", 0) * 100),
        "quality_risk": int(quality_risk.get("score", 0) * 100),
        "maintenance_risk": int(maintenance_risk.get("score", 0) * 100),
        "vulnerability": int(vulnerability.get("score", 0) * 100),
        "license": int(license_score.get("score", 0) * 100),
        "depscore": int(dep_score * 100)
    }


def normalize_deps_results(results, name, version, verbose=False):
    results = results.get("version", {}).get("projects")
    if not results:
        return False
    if not results[0].get("scorecardV2"):
        return False
    results = results[0].get("scorecardV2")
    total_score = int(results.get("score", 0) * 10)
    checks = results.get("check", [])
    scan_res = {
        "name": name,
        "version": version,
        "total_score": total_score
    }
    if not verbose:
        return scan_res
    for check in checks:
        scan_res[check.get("name")] = int(check.get("score", 0) * 10)
    return scan_res


def normalize_snyk_results(results, name, version, verbose=False):
    soup = BeautifulSoup(results, "html.parser")
    health = soup.find("div", {"class": "health"})
    if not health:
        return False
    health_score = health.find("div", {"class": "number"}).text
    scores = soup.find_all("ul", {"class": "scores"})
    scores = scores[0].find_all("span", {"class": "vue--pill__body"})
    security_score = scores[0].text
    popularity_score = scores[1].text
    maintenance_score = scores[2].text
    community_score = scores[3].text

    health_score = health_score.split(" / ")[0].replace("Package Health Score ", "")

    if not verbose:
        return {
            "name": name,
            "version": version,
            "health_score": health_score,
        }

    return {
        "name": name,
        "version": version,
        "health_score": health_score,
        "security_score": security_score,
        "popularity_score": popularity_score,
        "maintenance_score": maintenance_score,
        "community_score": community_score,
    }


def get_socket_results(package, file_type, verbose=False):
    package_name = package.get("name")
    package_version = package.get("version", "")
    try:
        url = f"https://socket.dev/api/{file_type}/package-info/score?name={package_name}"
        if package_version:
            url = f"{url}&version={package_version}"
        results = requests.get(url)
    except Exception as e:
        logging.debug(e)
        logging.warning(f"Failed to get results for {package_name} - probably not supported")
        return False
    results = normalize_socket_results(results.json(), package_name, package_version, verbose)
    if not results:
        return False
    results["full_report"] = url
    return results


def get_deps_results(package, file_type, verbose):
    package_name = urllib.parse.quote_plus(package.get("name"))
    package_version = package.get("version", "")
    url = f"https://deps.dev/_/s/{file_type}/p/{package_name}/v/{package_version}"
    try:
        results = requests.get(url)
        results.raise_for_status()
    except Exception as e:
        logging.debug(e)
        logging.warning(f"Failed to get results for {package_name} - probably not supported")
        return False
    results = normalize_deps_results(results.json(), package_name, package_version, verbose)
    if not results:
        return False
    return results


def get_snyk_results(package, file_type, verbose):
    scan_results = []

    if file_type == "npm":
        file_type = "npm-package"
    if file_type == "pypi":
        file_type = "python"
    if file_type == "go":
        file_type = "golang"

    package_name = package.get("name")
    url = f"https://snyk.io/advisor/{file_type}/{package_name}"
    results = requests.get(url)
    results = normalize_snyk_results(results.content, package_name, "", verbose)
    if not results:
        logging.warning(f"Failed to get results for {package_name} - probably not supported")
        return False
    results["full_report"] = url
    scan_results.append(results)
    return scan_results


def check_if_in_repo(path):
    try:
        _ = git.Repo(path).git_dir
        return True
    except git.exc.InvalidGitRepositoryError:
        return False


def get_file_type(path):
    file_name = os.path.basename(path)
    if check_if_in_repo(path):
        path = "" if path in [".", "./", "/"] else path
        stdout = subprocess.run(["github-linguist", path, "--json"], capture_output=True)
        stdout = stdout.stdout.decode("utf-8")
        stdout = json.loads(stdout)
        return stdout.keys()[0]
    if "." in file_name:
        file_extension = file_name.split(".")[-1]
    else:
        file_extension = os.path.basename(path)
    if file_type := EXTENSIONS_TO_LANGUAGE.get(file_extension):
        file_type = normalize_package_type(file_type.lower())
        return file_type
    else:
        logging.warning(f"File extension {file_extension} not supported")
        return ""


def get_dependencies_from_file(path):
    file_type = get_file_type(path)
    file_name = os.path.basename(path)
    dependencies = []
    pattern = ""
    if file_name in DEPENDENCIES_TO_FILE.values():
        return _handle_dependencies_declaration(path, file_type)
    elif file_type == "npm":
        pattern = r"^(?:import\s+(?:[\w*\s{},]*)\s+from\s+)?[\"']([^\"']+)[\"']|const\s+\w+\s*=\s*require\([\"']([^\"']+)[\"']\);"
    elif file_type == "pypi":
        pattern = r"^(?:from\s+([\w.]+)\s+import\s+|import\s+)([\w.]+)"
    elif file_type == "go":
        pattern = r"import\s+(?:[\w.]+\s+)?[\"']([\w/\-_.]+)[\"']"
    elif file_type == "gem":
        pattern = r"(?:require|require_relative|load)\s+['\"]([^'\"]+)['\"]"
    elif file_type == "maven":
        pattern = r"import\s+(static\s+)?([\w\.]+(?:\.\*)?);"
    elif file_type == "php":
        pattern = r"(?:use\s+(?:function\s+|const\s+)?|require(?:_once)?|include(?:_once)?)\s+(?:\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*\\?)*\s*(?:as\s+)?([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*|['\"][^'\"]+['\"]);"
    elif file_type == "rust":
        pattern = r"use\s+([a-zA-Z0-9_::\*]+)(?:\s+as\s+[a-zA-Z0-9_]+)?;"
    else:
        logging.warning(f"File type {file_type} not supported")
        return file_type, dependencies

    with open(path, "r") as f:
        for line in f.readlines():
            if match := re.match(pattern, line):
                for group in match.groups():
                    if group:
                        if "." in group:
                            group = group.split(".")[0]
                        dependencies.append({"name": group, "version": ""})
    return file_type, dependencies


def normalize_package_type(package_type):
    if package_type == "python" or package_type == "pip":
        return "pypi"
    if package_type == "javascript" or package_type == "js" or package_type == "typescript" or package_type == "ts":
        return "npm"
    if package_type == "golang":
        return "go"
    if package_type == "ruby":
        return "gem"
    if package_type == "java":
        return "maven"
    return package_type


def collect_results(dependencies, file_type, verbose=False):
    report = []
    for dependency in dependencies:
        dependency_report = {}
        for vendor in SUPPORTED_TYPES_BY_VENDOR.keys():
            if file_type in SUPPORTED_TYPES_BY_VENDOR[vendor]:
                if vendor == "socket":
                    results = get_socket_results(dependency, file_type, verbose)
                    if not results:
                        continue
                    dependency_report["socket"] = results
                if vendor == "deps":
                    results = get_deps_results(dependency, file_type, verbose)
                    if not results:
                        continue
                    dependency_report["deps"] = results
                    if vendor == "snyk":
                        results = get_snyk_results(dependency, file_type, verbose)
                        if not results:
                            continue
                        dependency_report["snyk"] = results
        if not dependency_report:
            dependency_report = {"name": dependency.get("name"), "version": dependency.get("version"), "error": "could not find results with any vendor"}
        report.append({f"{file_type}/{dependency.get('name')}": dependency_report})
    return report


def collect_results_by_vendor(dependencies, file_type):
    report = []
    for vendor in SUPPORTED_TYPES_BY_VENDOR.keys():
        if file_type in SUPPORTED_TYPES_BY_VENDOR[vendor]:
            if vendor == "socket":
                results = get_socket_results(dependencies, file_type, False)
                if not results:
                    continue
                report.append({"socket": results})
            if vendor == "deps":
                results = get_deps_results(dependencies, file_type, False)
                if not results:
                    continue
                report.append({"deps": results})
            if vendor == "snyk":
                results = get_snyk_results(dependencies, file_type, False)
                if not results:
                    continue
                report.append({"snyk": results})
    return report


def get_high_risk_packages(res):
    high_risk_packages = []
    for package in res:
        package_res = package.values()
        if package.get("error"):
            logging.warning(package["error"])
            continue
        for package in package_res:
            if package.get("socket"):
                logging.info(f"Found socket results for {package['socket']['name']} - score: {package['socket'].get('supply_chain_risk')}")
                if package["socket"].get("supply_chain_risk") >= 50:
                    high_risk_packages.append(package)
            if package.get("deps"):
                logging.info(f"Found deps results for {package['deps']['name']} - score: {package['deps'].get('total_score')}")
                if package["deps"].get("total_score") >= 50:
                    high_risk_packages.append(package)
            if package.get("snyk"):
                logging.info(f"Found snyk results for {package['snyk']['name']} - score: {package['snyk'].get('health_score')}")
                if package["snyk"].get("health_score") >= 50:
                    high_risk_packages.append(package)
    return high_risk_packages


def analyze_repo(repo, verbose=False):
    all_dependencies = {}
    mal_dependencies = []
    if not re.compile(r"^(?:https?|git)?(://)?(www\.)?(github|bitbucket|gitlab)").match(repo.lower()):
        logging.warning("Repo must be a valid git url")
    with tempfile.TemporaryDirectory() as temp_dir:
        git.Repo.clone_from(repo, temp_dir)
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                path = os.path.join(root, file)
                file_type, dependencies = get_dependencies_from_file(path)
                if not file_type:
                    continue
                if not all_dependencies.get(file_type):
                    all_dependencies[file_type] = []
                all_dependencies[file_type].extend(dependencies)
    for file_type, dependencies in all_dependencies.items():
        unique_packages = {}
        for dependency in dependencies:
            name = dependency['name']
            version = dependency['version']

            if name not in unique_packages or (name in unique_packages and not unique_packages[name]):
                unique_packages[name] = version
        dependencies = [{'name': k, 'version': v} for k, v in unique_packages.items()]
        results = collect_results(dependencies, file_type, verbose=verbose)
        mal_dependencies.extend(results)
    return mal_dependencies


def analyze_local(path):
    all_dependencies = {}
    mal_dependencies = []
    if not os.path.exists(path):
        logging.warning("Path does not exist")
    if os.path.isfile(path):
        file_type, dependencies = get_dependencies_from_file(path)
        if not all_dependencies.get(file_type):
            all_dependencies[file_type] = []
        all_dependencies[file_type].extend(dependencies)
    else:
        for root, dirs, files in os.walk(path):
            for file in files:
                path = os.path.join(root, file)
                file_type, dependencies = get_dependencies_from_file(path)
                if not all_dependencies.get(file_type):
                    all_dependencies[file_type] = []
                all_dependencies[file_type].extend(dependencies)
    for file_type, dependencies in all_dependencies.items():
        unique_packages = {}
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            name = dependency['name']
            version = dependency['version']

            if name not in unique_packages or (name in unique_packages and not unique_packages[name]):
                unique_packages[name] = version
        dependencies = [{'name': k, 'version': v} for k, v in unique_packages.items()]
        results = collect_results(dependencies, file_type)
        mal_dependencies.extend(results)
    return mal_dependencies


if __name__ == "__main__":
    # res = analyze_repo("https://github.com/guynachshon/iris")
    # res = analyze_local("/Users/guynachshon/Documents/code/CTFd")
    with open("res.json", "r") as f:
        res = json.load(f)
    high_risk_packages = get_high_risk_packages(res)
    with open("results.json", "w+") as f:
        json.dump(high_risk_packages, f, indent=4)
