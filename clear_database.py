#!/usr/bin/env python3
"""
Database Clear Script for AutoPost Application
This script clears all user data from MongoDB for a fresh start.
"""

import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# MongoDB Configuration (same as app.py)
MONGODB_URI = "mongodb://raafatsamy109:hQm3tZYWWEjNI2WS@ac-phjothd-shard-00-00.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-01.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-02.jdjy8pd.mongodb.net:27017/?replicaSet=atlas-12rk7b-shard-0&ssl=true&authSource=admin&retryWrites=true&w=majority&appName=Cluster0"

def clear_database():
    """Clear all user data from MongoDB"""
    try:
        # Connect to MongoDB
        print("🔌 Connecting to MongoDB...")
        client = MongoClient(MONGODB_URI)
        db = client.autopost
        
        # Test connection
        client.admin.command('ping')
        print("✅ Connected to MongoDB successfully!")
        
        # Get collection info before clearing
        users_collection = db.users
        user_count = users_collection.count_documents({})
        
        if user_count == 0:
            print("📭 Database is already empty!")
            return
        
        print(f"📊 Found {user_count} user(s) in database")
        
        # Confirm before clearing
        confirm = input("\n⚠️  WARNING: This will delete ALL user data!\n"
                       "Are you sure you want to continue? (yes/no): ").lower().strip()
        
        if confirm not in ['yes', 'y']:
            print("❌ Operation cancelled.")
            return
        
        # Clear all user data
        print("\n🗑️  Clearing database...")
        result = users_collection.delete_many({})
        
        print(f"✅ Successfully deleted {result.deleted_count} user(s)")
        print("🎉 Database cleared successfully!")
        
        # Verify database is empty
        remaining_users = users_collection.count_documents({})
        if remaining_users == 0:
            print("✅ Database is now empty and ready for fresh start!")
        else:
            print(f"⚠️  Warning: {remaining_users} user(s) still remain in database")
            
    except ConnectionFailure as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        print("Please check your MongoDB URI and network connection.")
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
    finally:
        if 'client' in locals():
            client.close()
            print("🔌 MongoDB connection closed.")

def show_database_info():
    """Show current database information"""
    try:
        print("🔍 Checking database status...")
        client = MongoClient(MONGODB_URI)
        db = client.autopost
        
        # Test connection
        client.admin.command('ping')
        print("✅ Connected to MongoDB successfully!")
        
        # Get collection info
        users_collection = db.users
        user_count = users_collection.count_documents({})
        
        print(f"\n📊 Database Information:")
        print(f"   • Database Name: {db.name}")
        print(f"   • Collection: users")
        print(f"   • Total Users: {user_count}")
        
        if user_count > 0:
            print(f"\n👥 User Details:")
            users = users_collection.find({}, {'user_id': 1, 'name': 1, 'email': 1, '_id': 0})
            for i, user in enumerate(users, 1):
                print(f"   {i}. {user.get('name', 'Unknown')} ({user.get('email', 'No email')})")
        
        client.close()
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

def main():
    """Main function"""
    print("=" * 50)
    print("🗄️  AutoPost Database Management Tool")
    print("=" * 50)
    
    while True:
        print("\n📋 Available options:")
        print("1. Show database information")
        print("2. Clear all user data (FRESH START)")
        print("3. Exit")
        
        choice = input("\nSelect an option (1-3): ").strip()
        
        if choice == '1':
            show_database_info()
        elif choice == '2':
            clear_database()
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid option. Please select 1, 2, or 3.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main() 