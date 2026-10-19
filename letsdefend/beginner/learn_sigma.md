# Lab 001: Detecting `Bitsadmin` File Downloads with Sigma

- **Platform:** LetsDefend
- **Focus:** Sigma rules, Windows process creation, and suspicious use of `bitsadmin.exe`
- **Date completed:** 19/10/2026

## Scenario
This lab examines a Sigma rule designed to detect certain uses of the Windows utility `bitsadmin.exe` to download files. 
The goal is to understand how the rule’s log source, selections, condition, fields, and tags work together.

## Investigation
1. Opened `proc_creation_win_bitsadmin_download.yml` using notepad in the `ChallengeFile` folder and reviewed its sections.
2. Checked the `logsource` section to identify the event category monitored by the rule: `process_creation`.
3. Reviewed the `detection` selections and condition. The rule checks for `bitsadmin.exe` and specified command-line patterns, including `/transfer`, `/create`, `/addfile`, and `http`.
4. Reviewed the `fields` and `tags` sections to identify the fields included for investigation and the ATT&CK tag listed in the rule.

## Findings
- The rule targets `bitsadmin.exe`.
- The rule monitors process-creation events.
- Its condition requires `selection_img` to match and then either `selection_cmd` or all matching `selection_cli_*` selections to match.
- The `CommandLine` field is useful for seeing the command and arguments used to start the process. (This was in the questions therefore i feel obligated to mention it)
- The rule’s first ATT&CK tactic tag is `attack.defense-evasion`.

## Conclusion
For a real alert, review the full command line, the user and host involved, the parent process, timestamps, and any downloaded file or related network activity. 
Follow the organization’s incident-response procedures and escalate if the evidence supports malicious activity.

## What I learned
- Sigma rules use named selections and a condition to describe how event data should match.
- `CommandLine` shows the command and arguments used to start a process, while `ParentCommandLine` describes the command that started its parent process. (Mostly a kind reminder for me here :)..)
- A detection is an investigative lead.. context is needed to determine whether activity is malicious.

## References
- LetsDefend: Learn Sigma lab
- Sigma rule reviewed: `proc_creation_win_bitsadmin_download.yml`

Lots of appreciation to whoever read this writeup. Thank you for your time :)
