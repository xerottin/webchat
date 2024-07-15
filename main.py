from contextlib import asynccontextmanager
from typing import List, Annotated
from fastapi import Depends, FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from databases import Database
from pydantic.deprecated.copy_internals import Model
from sqlalchemy import create_engine, MetaData

from models import users, messages
from schemas import UserInDB, User, TokenData, Token

DATABASE_URL = "postgresql://postgres:1111@localhost:5432/webchat"

database = Database(DATABASE_URL)
metadata = MetaData()

engine = create_engine(DATABASE_URL)
metadata.create_all(engine)


def fake_answer_to_everything_ml_model(x: float):
    return x * 42


ml_models = {}


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.create_all)


async def delete_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.drop_all)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await delete_tables()
    print('base clean')
    await create_tables()
    print('base ready')
    yield
    print('turn off')


app = FastAPI(lifespan=lifespan)


@app.get("/predict")
async def predict(x: float):
    result = ml_models["answer_to_everything"](x)
    return {"result": result}


SECRET_KEY = "6f8992ef1bff58a2927017951eaa6ee97202849bc7c0cd995f9bc84e484a53b7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(username: str) -> UserInDB | None:
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    if user:
        return UserInDB(**dict(user))


async def create_user(user: UserInDB):
    query = users.insert().values(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=user.hashed_password,
        disabled=user.disabled
    )
    await database.execute(query)


async def authenticate_user(username: str, password: str) -> UserInDB | None:
    user = await get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
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
    user = await get_user(token_data.username)
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
    existing_user = await get_user(user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    hashed_password = get_password_hash(user.hashed_password)
    user.hashed_password = hashed_password
    await create_user(user)
    return user


@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = await authenticate_user(form_data.username, form_data.password)
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
async def websocket_endpoint(websocket: WebSocket, client_id: int):
    try:
        await manager.connect(websocket, client_id)
        try:
            while True:
                data = await websocket.receive_text()
                message_data = data.split(':', 1)
                if len(message_data) == 2:
                    receiver_id, content = int(message_data[0]), message_data[1]
                    receiver = await get_user_by_client_id(receiver_id)
                    if receiver:
                        query = messages.insert().values(
                            sender_id=client_id,
                            receiver_id=receiver_id,
                            content=content,
                            timestamp=datetime.utcnow()
                        )
                        await database.execute(query)
                        await manager.broadcast(f"User {client_id} to User {receiver_id}: {content}")
                    else:
                        await websocket.send_text("Receiver not found")
                else:
                    await websocket.send_text("Invalid message format. Use 'receiver_id:content'")
        except WebSocketDisconnect:
            manager.disconnect(websocket)
    except HTTPException as _:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)


async def get_user_by_client_id(client_id: int) -> UserInDB | None:
    query = users.select().where(users.c.client_id == client_id)
    user = await database.fetch_one(query)
    if user:
        return UserInDB(**dict(user))
