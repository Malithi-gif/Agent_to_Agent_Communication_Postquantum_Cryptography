import asyncio
import json
import httpx

async def main():
    task = {
        "origin": "ORD",
        "destination": "JFK",
        "date": "2026-08-14",
        "max_price": 500,
        "auto_book": True,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post("http://127.0.0.1:8001/task", json=task)
        r.raise_for_status()
        print(json.dumps(r.json(), indent=2))

if __name__ == "__main__":
    asyncio.run(main())
