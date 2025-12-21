"""
Database Initialization Script
Creates tables and seeds default admin user
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db
from models import User

def init_database():
    """Initialize database with tables and default user"""
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created")
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        
        if not admin:
            # Create default admin user
            admin = User(
                username='admin',
                email='admin@casescope.local',
                full_name='Administrator',
                role='administrator',
                is_active=True
            )
            admin.set_password('admin')
            
            db.session.add(admin)
            db.session.commit()
            
            print("✓ Default admin user created")
            print("  Username: admin")
            print("  Password: admin")
            print("  Role: administrator")
        else:
            print("✓ Admin user already exists")
        
        print("\n✅ Database initialization complete!")
        print(f"   Total users: {User.query.count()}")

if __name__ == '__main__':
    init_database()
