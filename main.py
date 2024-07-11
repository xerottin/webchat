from typing import List, Annotated
from fastapi import Depends, FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError

app = FastAPI()

SECRET_KEY = "6f8992ef1bff58a2927017951eaa6ee97202849bc7c0cd995f9bc84e484a53b7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Fake users database
fake_users_db = {
    "johndoe": {
        "client_id": 1,
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "disabled": False,
    },
    "alice": {
        "client_id": 2,
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$KIXVw5HLV8OfpQOwzv4ADe2OhQOedQEVt.QV7KHHR9h9J/UdH9JBi",
        # Hashed password for "password"
        "disabled": False,
    },
}

# Fake messages database
fake_messages_db = []


# Schemas
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


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


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/register", response_model=User)
async def register(user: UserInDB):
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    hashed_password = get_password_hash(user.hashed_password)
    user_data = user.model_dump()
    user_data["hashed_password"] = hashed_password
    user_data["token"] = ""
    fake_users_db[user.username] = user_data
    return user


@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
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

    @staticmethod
    async def send_personal_message(message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection["websocket"].send_text(message)


manager = ConnectionManager()


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: int, token: str = Depends(oauth2_scheme)):
    user = await get_current_user(token)
    if user.client_id != client_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

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
