import re


class LogParser:

    def parse_line(self, line):

        if "Failed password" in line:

            match = re.search(
                r"Failed password for (?:invalid user )?(\S+) from (\S+)",
                line
            )

            if match:
                return {
                    "event_type": "authentication_failure",
                    "username": match.group(1),
                    "source_ip": match.group(2)
                }

        return None
