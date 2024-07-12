from sqlalchemy import MetaData, Table, Column, Integer, String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.sql import func

metadata = MetaData()


users = Table(
    "users",
    metadata,
    Column("client_id", Integer, primary_key=True),
    Column("username", String, unique=True, nullable=False),
    Column("email", String, unique=True, nullable=False),
    Column("full_name", String),
    Column("hashed_password", String, nullable=False),
    Column("disabled", Boolean, default=False),
)

messages = Table(
    "messages",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("sender_id", Integer, ForeignKey("users.client_id")),
    Column("receiver_id", Integer, ForeignKey("users.client_id")),
    Column("content", Text, nullable=False),
    Column("timestamp", DateTime, server_default=func.now()),
)