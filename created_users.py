from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # ADDED THIS LINE: Create the database tables from your app.py models
    db.create_all()

    # Optional: Clear existing users to avoid "Duplicate Entry" errors
    User.query.delete()
    
    # Create Admin account
    admin = User(
        username="admin",
        password_hash=generate_password_hash("admin123"),
        role="admin"
    )

    # Create Client account
    client = User(
        username="client",
        password_hash=generate_password_hash("client123"),
        role="client"
    )

    db.session.add(admin)
    db.session.add(client)
    db.session.commit()
    
    print("------------------------------------------")
    print("SUCCESS: Users created and database initialized!")
    print("ADMIN:  admin  /  admin123")
    print("CLIENT: client /  client123")
    print("------------------------------------------")