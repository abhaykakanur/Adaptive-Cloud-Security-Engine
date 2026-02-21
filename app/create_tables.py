from app.database import engine, Base
from app.models import User


Base.metadata.create_all(bind=engine)

print("✅ Tables created successfully")
