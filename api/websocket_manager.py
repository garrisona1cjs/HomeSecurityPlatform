from fastapi import WebSocket

# Active websocket connections
connections: set[WebSocket] = set()

# Event queue used by dispatcher
event_queue = []


async def broadcast(payload):

    dead_connections = []

    for ws in connections:

        try:
        
            await ws.send_json(payload)

        except Exception:
            dead_connections.append(ws)

    # Remove broken sockets
    for ws in dead_connections:
        connections.discard(ws)