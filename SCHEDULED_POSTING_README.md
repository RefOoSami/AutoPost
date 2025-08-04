# Scheduled Posting Feature

## 🎯 Overview

The **Scheduled Posting** feature allows users to schedule Facebook posts for future publication. Posts are automatically published at the specified date and time using a background scheduler.

## ✨ Features

### 📅 **Date & Time Selection**

- Choose exact date and time for post publication
- Real-time validation (must be in the future)
- User-friendly datetime picker interface

### 🔄 **Background Scheduler**

- Automatic post publication at scheduled times
- Runs every 30 seconds to check for due posts
- Handles multiple scheduled posts simultaneously
- Graceful error handling and status updates

### 📊 **Post Status Tracking**

- **Scheduled**: Post is waiting to be published
- **Published**: Post was successfully published to all groups
- **Partial**: Post was published to some groups, failed for others
- **Failed**: Post failed to publish to any groups

### 🗂️ **History & Management**

- View all scheduled and published posts
- Cancel scheduled posts before publication
- Detailed post results and error information
- Persistent storage in MongoDB

## 🚀 How to Use

### 1. **Schedule a Post**

1. Go to **Create Post** section
2. Select an account, groups, and poster
3. Set the desired date and time using the datetime picker
4. Click **"Schedule Post"** button
5. Confirm the scheduling

### 2. **View Scheduled Posts**

1. Click the **clock icon** in the sidebar
2. View all your scheduled and published posts
3. See status badges, timing information, and results

### 3. **Cancel Scheduled Posts**

1. Go to **Scheduled & History** section
2. Find the scheduled post you want to cancel
3. Click the **"Cancel"** button
4. Confirm the cancellation

## 🏗️ Technical Implementation

### **Backend Components**

#### **Database Schema**

```javascript
// scheduled_posts collection
{
  _id: ObjectId,
  user_id: String,
  group_ids: [String],
  main_caption: String,
  cookies: String,
  scheduled_time: Date,
  poster_name: String,
  account_name: String,
  groups: [String],
  images: [{
    name: String,
    caption: String,
    data: String // base64 encoded
  }],
  status: String, // 'scheduled', 'published', 'partial', 'failed'
  result: Object, // Post results and errors
  created_at: Date,
  published_at: Date
}
```

#### **API Endpoints**

- `POST /schedule_post` - Schedule a new post
- `GET /get_scheduled_posts` - Get user's scheduled posts
- `POST /delete_scheduled_post` - Cancel a scheduled post
- `POST /post` - Enhanced to handle scheduled posts

#### **Background Scheduler**

- **Thread-based scheduler** running every 30 seconds
- **Automatic startup** when Flask app starts
- **Graceful shutdown** when app stops
- **Error handling** for failed posts

### **Frontend Components**

#### **New UI Elements**

- **Sidebar Icon**: Clock icon for Scheduled & History
- **Date/Time Picker**: HTML5 datetime-local input
- **Schedule Button**: Separate from immediate post button
- **Status Cards**: Visual representation of post status

#### **JavaScript Functions**

- `schedulePost()` - Handle post scheduling
- `loadScheduledPosts()` - Load scheduled posts from API
- `displayScheduledPosts()` - Render posts in UI
- `deleteScheduledPost()` - Cancel scheduled posts

## 🔧 Configuration

### **Scheduler Settings**

```python
# Check interval (seconds)
SCHEDULER_INTERVAL = 30

# MongoDB collection
SCHEDULED_POSTS_COLLECTION = "scheduled_posts"
```

### **Post Status Types**

- `scheduled`: Waiting for publication
- `published`: Successfully published
- `partial`: Partially published (some groups failed)
- `failed`: Failed to publish to any groups

## 📋 Database Operations

### **Saving Scheduled Posts**

```python
def save_scheduled_post(user_id, post_data):
    post_data['user_id'] = user_id
    post_data['created_at'] = datetime.utcnow()
    post_data['status'] = 'scheduled'
    return db.scheduled_posts.insert_one(post_data)
```

### **Getting Due Posts**

```python
def get_due_posts():
    now = datetime.utcnow()
    return db.scheduled_posts.find({
        "status": "scheduled",
        "scheduled_time": {"$lte": now}
    })
```

### **Updating Post Status**

```python
def update_post_status(post_id, status, result=None):
    update_data = {"status": status}
    if result:
        update_data["result"] = result
        update_data["published_at"] = datetime.utcnow()
    db.scheduled_posts.update_one({"_id": ObjectId(post_id)}, {"$set": update_data})
```

## 🛡️ Error Handling

### **Scheduler Errors**

- **Individual post failures** don't affect other posts
- **Database connection errors** are logged and retried
- **Facebook API errors** are captured and stored
- **Temporary file cleanup** on errors

### **User Feedback**

- **Real-time notifications** for scheduling success/failure
- **Detailed error messages** for troubleshooting
- **Status badges** for quick visual feedback
- **Confirmation dialogs** for destructive actions

## 🔄 Workflow

### **Scheduling Process**

1. User selects post parameters (account, groups, poster)
2. User sets future date/time
3. Frontend validates date/time
4. Backend saves post to MongoDB
5. User receives confirmation
6. Post appears in Scheduled & History

### **Publication Process**

1. Scheduler checks for due posts every 30 seconds
2. Due posts are processed in background
3. Images are converted from base64 to files
4. Posts are published to Facebook groups
5. Results are captured and stored
6. Post status is updated in database
7. User can view results in Scheduled & History

## 🧪 Testing

### **Manual Testing**

1. Schedule a post for 1-2 minutes in the future
2. Wait for scheduled time
3. Check Scheduled & History for status update
4. Verify post appears on Facebook groups

### **Automated Testing**

Run the test script:

```bash
python test_scheduler.py
```

## 📝 Notes

### **Important Considerations**

- **App must be running** for scheduler to work
- **Scheduled posts persist** across app restarts
- **Facebook cookies** must remain valid
- **Image storage** uses base64 encoding in database
- **Temporary files** are cleaned up after processing

### **Performance**

- **Scheduler interval**: 30 seconds (configurable)
- **Background processing**: Non-blocking
- **Database queries**: Optimized with indexes
- **Memory usage**: Minimal for long-running scheduler

### **Security**

- **User authentication** required for all operations
- **Data isolation** by user_id
- **Input validation** on all endpoints
- **Error messages** don't expose sensitive data

## 🎉 Benefits

1. **Time Management**: Schedule posts during optimal hours
2. **Automation**: No manual intervention required
3. **Reliability**: Background processing with error handling
4. **Transparency**: Clear status tracking and history
5. **Flexibility**: Cancel or modify scheduled posts
6. **Scalability**: Handle multiple scheduled posts efficiently
