# notifications.py
import httpx

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"

async def send_push_notification(token: str, title: str, body: str):
    message = {
        "to": token,
        "sound": "default",
        "title": title,
        "body": body,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(EXPO_PUSH_URL, json=message)
        return response.json()
