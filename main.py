from typing import List, Annotated
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

app = FastAPI()

# users_database
fake_users_db = {
    "johndoe": {
        "client_id": 1,
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "client_id": 2,
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": False,
    },
}

# fake database
fake_messages_db = []


# Schemas
class User(BaseModel):
    client_id: int
    username: str
    full_name: str
    email: str
    disabled: bool


class UserInDB(User):
    hashed_password: str


class MessageCreate(BaseModel):
    receiver_id: int
    content: str


class Message(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    timestamp: datetime

    class Config:
        orm_mode = True


def fake_hash_password(password: str):
    return "fakehashed" + password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[dict] = []

    async def connect(self, websocket: WebSocket, client_id: int):
        await websocket.accept()
        self.active_connections.append({"websocket": websocket, "client_id": client_id})

    def disconnect(self, websocket: WebSocket):
        self.active_connections = [conn for conn in self.active_connections if conn["websocket"] != websocket]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection["websocket"].send_text(message)


manager = ConnectionManager()


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: int):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            message_data = data.split(':', 1)
            if len(message_data) == 2:
                receiver_id, content = int(message_data[0]), message_data[1]
                receiver = next((user for user in fake_users_db.values() if user['client_id'] == receiver_id), None)
                if receiver:
                    db_message = {
                        "id": len(fake_messages_db) + 1,
                        "sender_id": client_id,
                        "receiver_id": receiver_id,
                        "content": content,
                        "timestamp": datetime.utcnow()
                    }
                    fake_messages_db.append(db_message)
                    await manager.broadcast(f"User {client_id} to User {receiver_id}: {content}")
                else:
                    await websocket.send_text("Receiver not found")
            else:
                await websocket.send_text("Invalid message format. Use 'receiver_id:content'")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/messages/{client_id}", response_model=List[Message])
async def read_messages(
        client_id: int,
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    if current_user.client_id != client_id:
        raise HTTPException(status_code=403, detail="Not authorized to view these messages")
    user_messages = [
        message for message in fake_messages_db
        if message['sender_id'] == client_id or message['receiver_id'] == client_id
    ]
    return user_messages
