from fastapi import WebSocket

connections = set()

event_queue = []


async def broadcast(payload):

    dead = []

    for ws in list(connections):

        try:

            await ws.send_json(payload)

        except:

            dead.append(ws)

    for ws in dead:

        connections.discard(ws)