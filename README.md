# Linux Log Generator

Synthetic Linux syslog generator for testing log analysis systems.

## Features

- Generates realistic syslog entries (authentication, system operations, boot sequences)
- Configurable anomaly injection (privilege escalation, memory pressure, disk errors, etc.)
- Supports Docker deployment

## Installation & Run
```
git clone https://github.com/ekAn97/log_generator
cd log_generator
docker compose build
docker compose up
```

**Disclaimer**: Log file currently is accessed within the container only.


