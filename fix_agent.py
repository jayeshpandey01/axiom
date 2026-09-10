with open("controller/agent.py", "r") as f:
    text = f.read()

bandit_func = """
def parse_bandit_output(output_file: Path) -> dict[str, Any]:
    \"\"\"Parse Bandit SAST JSON report.\"\"\"
    default_empty = {
        "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        "findings": [],
        "scanned_files_count": 0,
        "total_rules_evaluated": 0,
    }
    if not output_file.exists() or output_file.stat().st_size == 0:
        return default_empty

    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Bandit JSON output from %s: %s", output_file, exc)
        return default_empty

    analyzer = BanditAnalyzer()
    return analyzer.analyze(data)

"""

# Insert the function before `SCANNER_PARSERS = {`
text = text.replace("SCANNER_PARSERS = {", bandit_func + "\nSCANNER_PARSERS = {")

# Insert the mapping
text = text.replace('"sast-gitleaks": parse_gitleaks_output,\n}', '"sast-gitleaks": parse_gitleaks_output,\n    "sast-bandit": parse_bandit_output,\n}')

with open("controller/agent.py", "w") as f:
    f.write(text)

