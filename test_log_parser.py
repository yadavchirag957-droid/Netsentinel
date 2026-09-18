from log_parser import LogParser


parser = LogParser()

test_line = (
    "Sep 15 20:30:01 server sshd[1234]: "
    "Failed password for kali from 192.168.56.3 port 54321 ssh2"
)

result = parser.parse_line(test_line)

print(result)
