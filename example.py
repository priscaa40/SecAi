"""Minimal local example for the SecAi agent pipeline."""

from secai import database
from secai.agent.workflow import process_event
from secai.event_sources import normalizer


def main() -> None:
    database.init_db()
    database.ensure_demo_site()
    event = normalizer.normalize_event(
        {
            "site_id": "demo-site",
            "source": "demo",
            "event_type": "http_request",
            "method": "GET",
            "path": "/products",
            "query": "id=1 OR 1=1--",
            "status_code": 200,
            "ip": "198.51.100.23",
            "signals": [],
            "metadata": {},
        }
    )
    stored_event = database.insert_event(event)
    incident = process_event(stored_event)
    print(incident)


if __name__ == "__main__":
    main()
