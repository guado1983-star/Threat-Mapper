Run the ThreatMapper pipeline against a log file and report the results.

Steps:
1. Run `python threat_mapper.py $ARGUMENTS` from the project root (Threat-Mapper/).
   - If no argument is given, the default `logs/sample_attack.log` is used.
   - If the user passed a log file path, forward it as the first positional argument.
2. Capture and display the full output — parsed events, summary, MITRE mapping, threat scores, and SOAR actions.
3. After the run completes, report:
   - How many events were parsed
   - The top threat source and its score
   - Any SOAR incident reports written to reports/
   - Any errors or unmatched log lines
