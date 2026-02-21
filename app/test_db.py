from app.database import engine


try:
    conn = engine.connect()
    print("✅ Connected to Supabase Database Successfully!")
    conn.close()
except Exception as e:
    print("❌ Connection Failed:")
    print(e)
