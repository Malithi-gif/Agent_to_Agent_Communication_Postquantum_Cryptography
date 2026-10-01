import asyncio
import json

import httpx

from config import ACCESS_TOKEN, AGENTS, CERT_FILE


async def main():
    task = {
        "origin": "ORD",
        "destination": "JFK",
        "date": "2026-08-14",
        "max_price": 500,
        "auto_book": True,
    }

    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }

    async with httpx.AsyncClient(
        timeout=60.0,
        verify=str(CERT_FILE),
    ) as client:
        r = await client.post(
            AGENTS["planner"]["url"] + "/task",
            json=task,
            headers=headers,
        )

        r.raise_for_status()
        print(json.dumps(r.json(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
