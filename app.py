from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session
import os
import json
import uuid
from werkzeug.utils import secure_filename
import requests
import re
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import secrets
from pymongo import MongoClient
from bson import ObjectId
import threading
import time
from datetime import datetime, timedelta, timezone

# Allow HTTP for local development only
if os.environ.get('FLASK_ENV') == 'development':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))  # Use environment variable or generate a secure secret key

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', "981431793001-bmb2incqc028f3phfjghi38r5t5ih0qq.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', "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")
GOOGLE_CALLBACK_URL = os.environ.get('GOOGLE_CALLBACK_URL', "https://autopost.koyeb.app/auth/oauth2callback")

# MongoDB Configuration
MONGODB_URI = os.environ.get('MONGODB_URI', "mongodb://raafatsamy109:hQm3tZYWWEjNI2WS@ac-phjothd-shard-00-00.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-01.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-02.jdjy8pd.mongodb.net:27017/?replicaSet=atlas-12rk7b-shard-0&ssl=true&authSource=admin&retryWrites=true&w=majority&appName=Cluster0")

# Initialize MongoDB client
try:
    client = MongoClient(MONGODB_URI)
    db = client.autopost
    print("Connected to MongoDB successfully!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    db = None

# Global variable to control the scheduler thread
scheduler_running = False
scheduler_thread = None

# Database helper functions
def get_user_data(user_id):
    """Get user data from MongoDB"""
    if db is None:
        return None
    return db.users.find_one({"user_id": user_id})

def save_user_data(user_id, data):
    """Save user data to MongoDB"""
    if db is None:
        return False
    try:
        result = db.users.update_one(
            {"user_id": user_id},
            {"$set": data},
            upsert=True
        )
        return True
    except Exception as e:
        return False

def get_user_accounts(user_id):
    """Get user's Facebook accounts"""
    user_data = get_user_data(user_id)
    return user_data.get('accounts', []) if user_data else []

def get_user_groups(user_id):
    """Get user's Facebook groups and categories"""
    user_data = get_user_data(user_id)
    return user_data.get('groups', []) if user_data else []

def save_user_accounts(user_id, accounts):
    """Save user's Facebook accounts"""
    user_data = get_user_data(user_id) or {}
    user_data['accounts'] = accounts
    result = save_user_data(user_id, user_data)
    return result

def save_user_groups(user_id, groups):
    """Save user's Facebook groups and categories"""
    user_data = get_user_data(user_id) or {}
    user_data['groups'] = groups
    result = save_user_data(user_id, user_data)
    return result

def save_complete_user_data(user_id, accounts, groups, posters=None):
    """Save complete user data including accounts, groups, and posters"""
    user_data = get_user_data(user_id) or {}
    user_data['accounts'] = accounts
    user_data['groups'] = groups
    if posters is not None:
        user_data['posters'] = posters
    return save_user_data(user_id, user_data)

def save_scheduled_post(user_id, post_data):
    """Save a scheduled post to MongoDB"""
    if db is None:
        return False
    try:
        # Ensure scheduled_time is a datetime object
        if isinstance(post_data.get('scheduled_time'), str):
            # Parse the local time from frontend
            local_time = datetime.fromisoformat(post_data['scheduled_time'])
            
            # Convert local time to UTC
            # Get the local timezone offset
            import time
            local_offset = time.timezone if time.daylight == 0 else time.altzone
            local_offset_hours = -local_offset / 3600  # Convert seconds to hours
            
            # Create timezone-aware local time
            from datetime import timedelta
            local_tz = timezone(timedelta(hours=local_offset_hours))
            local_time = local_time.replace(tzinfo=local_tz)
            
            # Convert to UTC
            scheduled_time = local_time.astimezone(timezone.utc)
            post_data['scheduled_time'] = scheduled_time
        
        post_data['user_id'] = user_id
        post_data['created_at'] = datetime.now(timezone.utc)
        post_data['status'] = 'scheduled'
        result = db.scheduled_posts.insert_one(post_data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error saving scheduled post: {e}")
        return False

def get_scheduled_posts(user_id):
    """Get all scheduled and published posts for a user"""
    if db is None:
        return []
    try:
        posts = list(db.scheduled_posts.find(
            {"user_id": user_id},
            {"_id": 1, "scheduled_time": 1, "status": 1, "poster_name": 1, "groups": 1, "account_name": 1, "created_at": 1, "result": 1}
        ).sort("scheduled_time", -1))
        
        # Convert ObjectId to string for JSON serialization
        for post in posts:
            post['_id'] = str(post['_id'])
            if 'created_at' in post:
                if hasattr(post['created_at'], 'isoformat'):
                    post['created_at'] = post['created_at'].isoformat()
                else:
                    post['created_at'] = str(post['created_at'])
            if 'scheduled_time' in post:
                if hasattr(post['scheduled_time'], 'isoformat'):
                    post['scheduled_time'] = post['scheduled_time'].isoformat()
                else:
                    post['scheduled_time'] = str(post['scheduled_time'])
        
        return posts
    except Exception as e:
        print(f"Error getting scheduled posts: {e}")
        return []

def update_post_status(post_id, status, result=None):
    """Update the status of a scheduled post"""
    if db is None:
        return False
    try:
        update_data = {"status": status}
        if result:
            update_data["result"] = result
            update_data["published_at"] = datetime.now(timezone.utc)
        
        db.scheduled_posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": update_data}
        )
        return True
    except Exception as e:
        print(f"Error updating post status: {e}")
        return False

def get_due_posts():
    """Get all posts that are due to be published"""
    if db is None:
        return []
    try:
        now = datetime.now(timezone.utc)
        due_posts = list(db.scheduled_posts.find({
            "status": "scheduled",
            "scheduled_time": {"$lte": now}
        }))
        print(f"[get_due_posts] Now: {now.isoformat()}, Due posts: {[str(p['_id']) for p in due_posts]}")
        
        # Debug: Show all scheduled posts and their times
        all_scheduled = list(db.scheduled_posts.find({"status": "scheduled"}))
        print(f"[get_due_posts] All scheduled posts: {len(all_scheduled)}")
        for post in all_scheduled:
            scheduled_time = post.get('scheduled_time', 'N/A')
            if hasattr(scheduled_time, 'isoformat'):
                scheduled_time = scheduled_time.isoformat()
            print(f"  - Post {str(post['_id'])}: scheduled for {scheduled_time}")
        
        return due_posts
    except Exception as e:
        print(f"Error getting due posts: {e}")
        return []

def delete_scheduled_post(post_id, user_id):
    """Delete a scheduled post"""
    if db is None:
        return False
    try:
        result = db.scheduled_posts.delete_one({
            "_id": ObjectId(post_id),
            "user_id": user_id,
            "status": "scheduled"
        })
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting scheduled post: {e}")
        return False

def get_and_mark_due_post():
    """Atomically get and mark a due post as processing"""
    if db is None:
        return None
    now = datetime.now(timezone.utc)
    return db.scheduled_posts.find_one_and_update(
        {
            "status": "scheduled",
            "scheduled_time": {"$lte": now}
        },
        {"$set": {"status": "processing"}},
        sort=[("scheduled_time", 1)]
    )

# Background scheduler function
def scheduler_worker():
    """Background worker that checks for due posts and publishes them (atomic version)"""
    global scheduler_running
    while scheduler_running:
        try:
            post = get_and_mark_due_post()
            if post:
                print(f"[Scheduler] Picked post {post['_id']} for processing at {datetime.now(timezone.utc).isoformat()}")
                try:
                    print(f"Publishing scheduled post {post['_id']}")
                    
                    # Parse cookies
                    cookies_text = post['cookies']
                    cookies = {}
                    for line in cookies_text.strip().split(';'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            cookies[key.strip()] = value.strip()
                    
                    # Prepare image files
                    image_files = []
                    for image_data in post['images']:
                        # Convert base64 to temporary file
                        import base64
                        image_data_b64 = image_data['data'].split(',')[1]
                        image_bytes = base64.b64decode(image_data_b64)
                        
                        # Save to temporary file
                        temp_filename = f"temp_{uuid.uuid4()}.jpg"
                        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
                        
                        with open(temp_filepath, 'wb') as f:
                            f.write(image_bytes)
                        
                        image_files.append({
                            'path': temp_filepath,
                            'caption': image_data.get('caption', '')
                        })
                    
                    results = []
                    errors = []
                    
                    # Post to each group
                    for group_id in post['group_ids']:
                        try:
                            # Extract Facebook data for this group
                            facebook_data = extract_facebook_data(group_id, cookies)
                            
                            # Upload images for each group
                            attachments = upload_images(image_files, facebook_data, cookies)
                            
                            # Create post for this group
                            result = create_post(group_id, post['main_caption'], attachments, facebook_data, cookies)
                            results.append({
                                'group_id': group_id,
                                'status': 'success',
                                'result': result
                            })
                            
                        except Exception as e:
                            errors.append({
                                'group_id': group_id,
                                'error': str(e)
                            })
                    
                    # Clean up temporary files
                    for image_file in image_files:
                        if os.path.exists(image_file['path']):
                            os.remove(image_file['path'])
                    
                    # Update post status
                    if results:
                        status = 'published' if not errors else 'partial'
                        result_data = {
                            'results': results,
                            'errors': errors,
                            'total_groups': len(post['group_ids']),
                            'successful_posts': len(results),
                            'failed_posts': len(errors)
                        }
                    else:
                        status = 'failed'
                        result_data = {'error': 'Failed to post to any groups'}
                    
                    update_post_status(str(post['_id']), status, result_data)
                    
                except Exception as e:
                    print(f"Error processing scheduled post {post['_id']}: {e}")
                    update_post_status(str(post['_id']), 'failed', {'error': str(e)})
            else:
                # No due post, sleep a bit
                time.sleep(5)
            
        except Exception as e:
            print(f"Scheduler error: {e}")
            time.sleep(5)

def start_scheduler():
    """Start the background scheduler"""
    global scheduler_running, scheduler_thread
    if not scheduler_running:
        scheduler_running = True
        scheduler_thread = threading.Thread(target=scheduler_worker, daemon=True)
        scheduler_thread.start()
        print("Scheduler started")

def stop_scheduler():
    """Stop the background scheduler"""
    global scheduler_running
    scheduler_running = False
    print("Scheduler stopped")

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_session_id():
    """Generate a session ID in the same format as Facebook's composer_session_id"""
    return str(uuid.uuid4())

def extract_facebook_data(group_id, cookies):
    """Extract necessary Facebook data from the group page"""
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'max-age=0',
        'dpr': '1.25',
        'priority': 'u=0, i',
        'sec-ch-prefers-color-scheme': 'dark',
        'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        'sec-ch-ua-full-version-list': '"Not)A;Brand";v="8.0.0.0", "Chromium";v="138.0.7204.184", "Google Chrome";v="138.0.7204.184"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-model': '""',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-platform-version': '"19.0.0"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'viewport-width': '1036',
    }

    params = {
        'locale': 'ar_AR',
    }

    try:
        response = requests.get(f'https://www.facebook.com/groups/{group_id}', params=params, cookies=cookies, headers=headers)
        
        # Extract data using regex
        userId = re.search(r'"userID":(\d+)', response.text).group(1)
        lsd = re.search(r'"LSD",\s*\[\s*\],\s*\{\s*"token":\s*"([^"]+)"', response.text).group(1)
        haste_session = re.search(r'"haste_session":\s*"([^"]+)"', response.text).group(1)
        hsi = re.search(r'"hsi":\s*"([^"]+)"', response.text).group(1)
        spin_r = re.search(r'"__spin_r":\s*(\d+)', response.text).group(1)
        spin_t = re.search(r'"__spin_t":\s*(\d+)', response.text).group(1)
        dtsg_token = re.search(r'"dtsg":\s*\{\s*"token":\s*"([^"]+)"', response.text).group(1)
        jazoest = re.search(r'jazoest=(\d+)', response.text).group(1)
        
        return {
            'userId': userId,
            'lsd': lsd,
            'haste_session': haste_session,
            'hsi': hsi,
            'spin_r': spin_r,
            'spin_t': spin_t,
            'dtsg_token': dtsg_token,
            'jazoest': jazoest
        }
    except Exception as e:
        raise Exception(f"Failed to extract Facebook data: {str(e)}")

def upload_images(image_files, facebook_data, cookies):
    """Upload images and return attachments with captions"""
    params = {
        'av': facebook_data['userId'],
        '__aaid': '0',
        '__user': facebook_data['userId'],
        '__a': '1',
        '__req': '2d',
        '__hs': facebook_data['haste_session'],
        'dpr': '1',
        '__ccg': 'GOOD',
        '__rev': facebook_data['spin_r'],
        '__hsi': facebook_data['hsi'],
        '__comet_req': '15',
        'locale': 'ar_AR',
        'fb_dtsg': facebook_data['dtsg_token'],
        'jazoest': facebook_data['jazoest'],
        'lsd': facebook_data['lsd'],
        '__spin_r': facebook_data['spin_r'],
        '__spin_b': 'trunk',
        '__spin_t': facebook_data['spin_t'],
        '__crn': 'comet.fbweb.CometGroupDiscussionRoute',
    }
    
    headers = {
        'accept': '*/*',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'origin': 'https://www.facebook.com',
        'priority': 'u=1, i',
        'referer': 'https://www.facebook.com/',
        'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    }
    
    attachments = []
    
    for image_data in image_files:
        image_path = image_data['path']
        caption = image_data.get('caption', None)
        
        files = {
            'source': (None, '8'),
            'profile_id': (None, facebook_data['userId']),
            'waterfallxapp': (None, 'comet'),
            'farr': (os.path.basename(image_path), open(image_path, 'rb'), 'image/jpeg'),
            'upload_id': (None, 'jsc_c_6'),
        }

        response = requests.post(
            'https://upload.facebook.com/ajax/react_composer/attachments/photo/upload',
            params=params,
            cookies=cookies,
            headers=headers,
            files=files,
        )
        
        photo_id = re.search(r'"photoID":\s*"([^"]+)"', response.text).group(1)
        
        attachment = {"photo": {"id": photo_id}}
        if caption:
            attachment["photo"]["message"] = {"text": caption}
        attachments.append(attachment)
    
    return attachments

def create_post(group_id, main_caption, attachments, facebook_data, cookies):
    """Create the post with images and captions"""
    variables_data = {
        "input": {
            "composer_entry_point": "inline_composer",
            "composer_source_surface": "group",
            "composer_type": "group",
            "logging": {
                "composer_session_id": generate_session_id()
            },
            "source": "WWW",
            "message": {
                "ranges": [],
                "text": main_caption
            },
            "with_tags_ids": None,
            "inline_activities": [],
            "text_format_preset_id": "0",
            "group_flair": {
                "flair_id": None
            },
            "attachments": attachments,
            "composed_text": {
                "block_data": ["{}"],
                "block_depths": [0],
                "block_types": [0],
                "blocks": [main_caption],
                "entities": ["[]"],
                "entity_map": "{}",
                "inline_styles": ["[]"]
            },
            "navigation_data": {
                "attribution_id_v2": "CometGroupDiscussionRoot.react,comet.group,via_cold_start,1754235110188,525586,2361831622,,"
            },
            "tracking": [None],
            "event_share_metadata": {
                "surface": "newsfeed"
            },
            "audience": {
                "to_id": group_id
            },
            "actor_id": facebook_data['userId'],
            "client_mutation_id": "3"
        },
        "feedLocation": "GROUP",
        "feedbackSource": 0,
        "focusCommentID": None,
        "gridMediaWidth": None,
        "groupID": None,
        "scale": 1,
        "privacySelectorRenderLocation": "COMET_STREAM",
        "checkPhotosToReelsUpsellEligibility": False,
        "renderLocation": "group",
        "useDefaultActor": False,
        "inviteShortLinkKey": None,
        "isFeed": False,
        "isFundraiser": False,
        "isFunFactPost": False,
        "isGroup": True,
        "isEvent": False,
        "isTimeline": False,
        "isSocialLearning": False,
        "isPageNewsFeed": False,
        "isProfileReviews": False,
        "isWorkSharedDraft": False,
        "hashtag": None,
        "canUserManageOffers": False,
        "__relay_internal__pv__CometUFIShareActionMigrationrelayprovider": True,
        "__relay_internal__pv__GHLShouldChangeSponsoredDataFieldNamerelayprovider": True,
        "__relay_internal__pv__GHLShouldChangeAdIdFieldNamerelayprovider": True,
        "__relay_internal__pv__CometUFI_dedicated_comment_routable_dialog_gkrelayprovider": False,
        "__relay_internal__pv__IsWorkUserrelayprovider": False,
        "__relay_internal__pv__CometUFIReactionsEnableShortNamerelayprovider": False,
        "__relay_internal__pv__FBReels_deprecate_short_form_video_context_gkrelayprovider": True,
        "__relay_internal__pv__FeedDeepDiveTopicPillThreadViewEnabledrelayprovider": False,
        "__relay_internal__pv__FBReels_enable_view_dubbed_audio_type_gkrelayprovider": False,
        "__relay_internal__pv__CometImmersivePhotoCanUserDisable3DMotionrelayprovider": False,
        "__relay_internal__pv__WorkCometIsEmployeeGKProviderrelayprovider": False,
        "__relay_internal__pv__IsMergQAPollsrelayprovider": False,
        "__relay_internal__pv__FBReelsMediaFooter_comet_enable_reels_ads_gkrelayprovider": True,
        "__relay_internal__pv__StoriesArmadilloReplyEnabledrelayprovider": True,
        "__relay_internal__pv__FBReelsIFUTileContent_reelsIFUPlayOnHoverrelayprovider": True,
        "__relay_internal__pv__GHLShouldChangeSponsoredAuctionDistanceFieldNamerelayprovider": True
    }

    data = {
        'av': facebook_data['userId'],
        '__aaid': '0',
        '__user': facebook_data['userId'],
        '__a': '1',
        '__req': '3a',
        '__hs': facebook_data['haste_session'],
        'dpr': '1',
        '__ccg': 'GOOD',
        '__rev': facebook_data['spin_r'],
        '__s': 'cegcrk:lhgzk1:f5bpkr',
        '__hsi': facebook_data['hsi'],
        '__comet_req': '15',
        'locale': 'ar_AR',
        'fb_dtsg': facebook_data['dtsg_token'],
        'jazoest': facebook_data['jazoest'],
        'lsd': facebook_data['lsd'],
        '__spin_r': facebook_data['spin_r'],
        '__spin_b': 'trunk',
        '__spin_t': facebook_data['spin_t'],
        '__crn': 'comet.fbweb.CometGroupDiscussionRoute',
        'fb_api_caller_class': 'RelayModern',
        'fb_api_req_friendly_name': 'ComposerStoryCreateMutation',
        'variables': json.dumps(variables_data),
        'server_timestamps': 'true',
        'doc_id': '24061662373461149',
    }

    headers = {
        'accept': '*/*, application/vnd.t1c.pxr-28-28',
        'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.facebook.com',
        'priority': 'u=1, i',
        'referer': f'https://www.facebook.com/groups/{group_id}?locale=ar_AR',
        'sec-ch-prefers-color-scheme': 'dark',
        'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        'sec-ch-ua-full-version-list': '"Not)A;Brand";v="8.0.0.0", "Chromium";v="138.0.7204.184", "Google Chrome";v="138.0.7204.184"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-model': '""',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-platform-version': '"19.0.0"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'x-asbd-id': '359341',
        'x-fb-friendly-name': 'ComposerStoryCreateMutation',
        'x-fb-lsd': facebook_data['lsd'],
    }

    response = requests.post('https://www.facebook.com/api/graphql/', cookies=cookies, headers=headers, data=data)
    return response.text

@app.route('/fetch_account_info', methods=['POST'])
def fetch_account_info():
    try:
        data = request.get_json()
        cookies_text = data.get('cookies')
        
        if not cookies_text:
            return jsonify({'success': False, 'error': 'Cookies are required'})
        
        # Parse cookies
        cookies = {}
        for line in cookies_text.strip().split(';'):
            if '=' in line:
                key, value = line.split('=', 1)
                cookies[key.strip()] = value.strip()
        # Headers for the request
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'max-age=0',
            'dpr': '1.25',
            'priority': 'u=0, i',
            'sec-ch-prefers-color-scheme': 'dark',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            'sec-ch-ua-full-version-list': '"Not)A;Brand";v="8.0.0.0", "Chromium";v="138.0.7204.184", "Google Chrome";v="138.0.7204.184"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-model': '""',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"19.0.0"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'viewport-width': '651',
        }
        
        params = {
            'locale': 'ar_AR',
        }
        
        # Get user ID from cookies
        user_id = cookies.get('c_user')
        if not user_id:
            return jsonify({'success': False, 'error': 'Could not extract user ID from cookies'})
        
        # Make request to Facebook profile page
        response = requests.get(f'https://www.facebook.com/{user_id}/', 
                              params=params, cookies=cookies, headers=headers)
        
        if response.status_code != 200:
            return jsonify({'success': False, 'error': f'Failed to fetch account info. Status: {response.status_code}'})
        
        # Extract account information using regex
        personal_user_id_match = re.search(r'"personal_user_id":"(\d+)"', response.text)
        profile_name = re.search(r'"__typename"\s*:\s*"User"\s*,\s*"name"\s*:\s*"([^"]+)"\s*,\s*"profile_picture"', response.text)
        profile_pic_match = re.search(r'"profilePicLarge":{"uri":"([^"]+)"', response.text)
        
        if not personal_user_id_match:
            return jsonify({'success': False, 'error': 'Could not extract account information'})
        
        personal_user_id = personal_user_id_match.group(1)
        profile_pic_url = profile_pic_match.group(1).replace('\\/', '/') if profile_pic_match else None
        profile_name = profile_name.group(1)
        
        return jsonify({
            'success': True,
            'account_name': profile_name,
            'user_id': personal_user_id,
            'profile_pic_url': profile_pic_url,
            'cookies': cookies_text
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/save_account', methods=['POST'])
def save_account():
    """Save account to MongoDB"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        user_id = session.get('user_id')
        
        # Get current user data
        user_data = get_user_data(user_id) or {}
        accounts = user_data.get('accounts', [])
        
        # Add new account
        new_account = {
            'account_name': data['account_name'],
            'user_id': data['user_id'],
            'profile_pic_url': data['profile_pic_url'],
            'cookies': data['cookies']
        }
        
        accounts.append(new_account)
        
        # Save to MongoDB
        save_result = save_user_accounts(user_id, accounts)
        
        if save_result:
            return jsonify({'success': True, 'message': 'Account saved successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save account'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/fetch_group_info', methods=['POST'])
def fetch_group_info():
    try:
        data = request.get_json()
        group_id = data.get('group_id')
        cookies_text = data.get('cookies')
        
        if not group_id or not cookies_text:
            return jsonify({'success': False, 'error': 'Group ID and cookies are required'})
        
        # Parse cookies
        cookies = {}
        for line in cookies_text.strip().split(';'):
            if '=' in line:
                key, value = line.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        # Headers for the request
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'max-age=0',
            'dpr': '1.25',
            'priority': 'u=0, i',
            'sec-ch-prefers-color-scheme': 'dark',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            'sec-ch-ua-full-version-list': '"Not)A;Brand";v="8.0.0.0", "Chromium";v="138.0.7204.184", "Google Chrome";v="138.0.7204.184"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-model': '""',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"19.0.0"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'viewport-width': '651',
        }
        
        params = {
            'locale': 'ar_AR',
        }
        
        # Make request to Facebook group page
        response = requests.get(f'https://www.facebook.com/groups/{group_id}', 
                              params=params, cookies=cookies, headers=headers)
        
        if response.status_code != 200:
            return jsonify({'success': False, 'error': f'Failed to fetch group info. Status: {response.status_code}'})
        
        # Extract group information using regex
        group_name_match = re.search(r'<title>(.*?)</title>', response.text)
        member_count_match = re.search(r'(\d+(?:\.\d+)?[KMB]?)\s*members', response.text)
        group_image_match = re.search(r'"profile_picture_120":{"uri":"([^"]+)"', response.text)
        
        if not group_name_match:
            return jsonify({'success': False, 'error': 'Could not extract group name'})
        
        group_name = group_name_match.group(1).strip()
        member_count = member_count_match.group(1) if member_count_match else 'Unknown'
        group_image_url = group_image_match.group(1).replace('\\/', '/') if group_image_match else None
        
        return jsonify({
            'success': True,
            'group_name': group_name,
            'member_count': member_count,
            'group_id': group_id,
            'group_image_url': group_image_url
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/save_group', methods=['POST'])
def save_group():
    """Save group to MongoDB"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        user_id = session.get('user_id')
        category_index = data.get('category_index', 0)  # Get category index
        
        # Get current user data
        user_data = get_user_data(user_id) or {}
        categories = user_data.get('groups', [])  # This stores categories
        
        # Check if categories exist
        if not categories:
            return jsonify({'success': False, 'error': 'No categories available. Please create a category first using the "Add Category" button.'})
        
        # Validate category index
        if category_index < 0 or category_index >= len(categories):
            return jsonify({'success': False, 'error': f'Invalid category index. Please select a valid category (0-{len(categories)-1})'})
        
        # Add new group to the specified category
        new_group = {
            'name': data['group_name'],
            'id': data['group_id'],
            'member_count': data['member_count'],
            'image_url': data.get('group_image_url')
        }
        
        categories[category_index]['groups'].append(new_group)
        
        # Save to MongoDB
        save_result = save_user_groups(user_id, categories)
        
        if save_result:
            return jsonify({'success': True, 'message': 'Group saved successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save group'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/save_poster', methods=['POST'])
def save_poster():
    """Save poster to MongoDB"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        user_id = session.get('user_id')
        
        # Get current user data
        user_data = get_user_data(user_id) or {}
        posters = user_data.get('posters', [])
        
        # Process images and create poster data
        poster_images = []
        for image_data in data['images']:
            # Convert base64 data to file-like object for storage
            poster_images.append({
                'name': image_data['name'],
                'caption': image_data['caption'],
                'data': image_data['data']  # This will be base64 encoded
            })
        
        # Add new poster
        new_poster = {
            'name': data['name'],
            'caption': data['caption'],
            'images': poster_images
        }
        
        posters.append(new_poster)
        
        # Save to MongoDB
        user_data['posters'] = posters
        save_result = save_user_data(user_id, user_data)
        
        if save_result:
            return jsonify({'success': True, 'message': 'Poster saved successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save poster'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/save_user_data', methods=['POST'])
def save_user_data_route():
    """Save complete user data to MongoDB"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        user_id = session.get('user_id')
        
        # Save complete user data
        if save_complete_user_data(user_id, data.get('accounts', []), data.get('groups', []), data.get('posters', [])):
            return jsonify({'success': True, 'message': 'Data saved successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save data'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_user_data', methods=['GET'])
def get_user_data_route():
    """Get user data from MongoDB"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        user_id = session.get('user_id')
        
        # Always get fresh data from MongoDB
        user_data = get_user_data(user_id)
        
        if user_data:
            accounts = user_data.get('accounts', [])
            groups = user_data.get('groups', [])
            posters = user_data.get('posters', [])
            
            # Add cache control headers to prevent caching
            response = jsonify({
                'success': True,
                'accounts': accounts,
                'groups': groups,
                'posters': posters
            })
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        else:
            response = jsonify({
                'success': True,
                'accounts': [],
                'groups': [],
                'posters': []
            })
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/post', methods=['POST'])
def post():
    try:
        # Get form data
        group_ids = request.form.getlist('group_ids[]')
        main_caption = request.form['main_caption']
        scheduled_date_time = request.form.get('scheduled_date_time', '').strip()
        
        # Validate group IDs
        if not group_ids or not any(group_ids):
            raise Exception("At least one group ID is required")
        
        # Remove empty group IDs
        group_ids = [gid.strip() for gid in group_ids if gid.strip()]
        
        if not group_ids:
            raise Exception("At least one valid group ID is required")
        
        # Parse cookies
        cookies_text = request.form['cookies']
        cookies = {}
        for line in cookies_text.strip().split(';'):
            if '=' in line:
                key, value = line.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        # Get uploaded files
        uploaded_files = request.files.getlist('images')
        image_captions = request.form.getlist('image_captions')
        
        # Save uploaded files and prepare image data
        image_files = []
        for i, file in enumerate(uploaded_files):
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Get caption for this file using the original file index
                caption = image_captions[i] if i < len(image_captions) and image_captions[i] else None
                image_files.append({
                    'path': filepath,
                    'caption': caption
                })
        
        # Check if this is a scheduled post
        if scheduled_date_time:
            try:
                # Parse the local time from frontend
                local_time = datetime.fromisoformat(scheduled_date_time)
                
                # Convert local time to UTC
                # Get the local timezone offset
                import time
                local_offset = time.timezone if time.daylight == 0 else time.altzone
                local_offset_hours = -local_offset / 3600  # Convert seconds to hours
                
                # Create timezone-aware local time
                from datetime import timedelta
                local_tz = timezone(timedelta(hours=local_offset_hours))
                local_time = local_time.replace(tzinfo=local_tz)
                
                # Convert to UTC
                scheduled_time = local_time.astimezone(timezone.utc)
                
                if scheduled_time <= datetime.now(timezone.utc):
                    raise Exception("Scheduled time must be in the future")
                
                # Save as scheduled post
                user_id = session.get('user_id')
                if not user_id:
                    raise Exception("User not authenticated")
                
                # Prepare scheduled post data
                scheduled_post_data = {
                    'group_ids': group_ids,
                    'main_caption': main_caption,
                    'cookies': cookies_text,
                    'scheduled_time': scheduled_time,  # This is already a datetime object
                    'poster_name': request.form.get('poster_name', 'Manual Post'),
                    'account_name': request.form.get('account_name', 'Unknown Account'),
                    'groups': request.form.getlist('group_names[]'),
                    'images': []  # Will be populated with base64 data
                }
                
                # Convert images to base64 for storage
                for image_file in image_files:
                    with open(image_file['path'], 'rb') as f:
                        import base64
                        image_data = base64.b64encode(f.read()).decode('utf-8')
                        scheduled_post_data['images'].append({
                            'name': os.path.basename(image_file['path']),
                            'caption': image_file.get('caption', ''),
                            'data': f"data:image/jpeg;base64,{image_data}"
                        })
                
                # Save scheduled post
                post_id = save_scheduled_post(user_id, scheduled_post_data)
                
                if post_id:
                    # Clean up uploaded files
                    for image_file in image_files:
                        if os.path.exists(image_file['path']):
                            os.remove(image_file['path'])
                    
                    return jsonify({
                        'success': True,
                        'message': f'Post scheduled for {scheduled_time.strftime("%Y-%m-%d %H:%M:%S")}',
                        'scheduled': True,
                        'post_id': post_id
                    })
                else:
                    raise Exception("Failed to save scheduled post")
                    
            except Exception as e:
                # Clean up uploaded files on error
                for image_file in image_files:
                    if os.path.exists(image_file['path']):
                        os.remove(image_file['path'])
                raise Exception(f"Error scheduling post: {str(e)}")
        
        # Immediate posting (existing logic)
        results = []
        errors = []
        
        # Post to each group
        for group_id in group_ids:
            try:
                # Extract Facebook data for this group
                facebook_data = extract_facebook_data(group_id, cookies)
                
                # Upload images for each group
                attachments = upload_images(image_files, facebook_data, cookies)
                
                # Create post for this group
                result = create_post(group_id, main_caption, attachments, facebook_data, cookies)
                results.append({
                    'group_id': group_id,
                    'status': 'success',
                    'result': result
                })
                
            except Exception as e:
                errors.append({
                    'group_id': group_id,
                    'error': str(e)
                })
        
        # Clean up uploaded files
        for image_file in image_files:
            if os.path.exists(image_file['path']):
                os.remove(image_file['path'])
        
        # Prepare response
        if not results and errors:
            raise Exception("Failed to post to any groups")
        
        return jsonify({
            'success': True, 
            'results': results,
            'errors': errors,
            'total_groups': len(group_ids),
            'successful_posts': len(results),
            'failed_posts': len(errors)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/schedule_post', methods=['POST'])
def schedule_post():
    """Schedule a post for later publication"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        user_id = session.get('user_id')
        
        # Validate required fields
        required_fields = ['group_ids', 'main_caption', 'cookies', 'scheduled_time', 'poster_name', 'account_name', 'images']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'})
        
        # Validate scheduled time
        try:
            # Parse the local time from frontend
            local_time = datetime.fromisoformat(data['scheduled_time'])
            
            # Convert local time to UTC
            # Get the local timezone offset
            import time
            local_offset = time.timezone if time.daylight == 0 else time.altzone
            local_offset_hours = -local_offset / 3600  # Convert seconds to hours
            
            # Create timezone-aware local time
            from datetime import timedelta
            local_tz = timezone(timedelta(hours=local_offset_hours))
            local_time = local_time.replace(tzinfo=local_tz)
            
            # Convert to UTC
            scheduled_time = local_time.astimezone(timezone.utc)
            
            if scheduled_time <= datetime.now(timezone.utc):
                return jsonify({'success': False, 'error': 'Scheduled time must be in the future'})
        except Exception as e:
            return jsonify({'success': False, 'error': f'Invalid scheduled time format: {str(e)}'})
        
        # Save scheduled post
        post_id = save_scheduled_post(user_id, data)
        
        if post_id:
            return jsonify({
                'success': True,
                'message': f'Post scheduled for {scheduled_time.strftime("%Y-%m-%d %H:%M:%S")}',
                'post_id': post_id
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save scheduled post'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_scheduled_posts', methods=['GET'])
def get_scheduled_posts_route():
    """Get all scheduled and published posts for the current user"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        user_id = session.get('user_id')
        posts = get_scheduled_posts(user_id)
        
        return jsonify({
            'success': True,
            'posts': posts
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_scheduled_post', methods=['POST'])
def delete_scheduled_post_route():
    """Delete a scheduled post"""
    try:
        if not session.get('authenticated'):
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        user_id = session.get('user_id')
        post_id = data.get('post_id')
        
        if not post_id:
            return jsonify({'success': False, 'error': 'Post ID is required'})
        
        success = delete_scheduled_post(post_id, user_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Scheduled post deleted successfully'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to delete scheduled post or post not found'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Initiate Google OAuth flow"""
    # Check if user is already authenticated
    if session.get('authenticated'):
        return redirect(url_for('index'))
    
    # Check if this is a GET request (show login page)
    if request.method == 'GET':
        return render_template('login.html')
    
    # POST request - initiate OAuth flow
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_CALLBACK_URL]
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
    )
    
    flow.redirect_uri = GOOGLE_CALLBACK_URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/auth/oauth2callback')
def callback():
    """Handle Google OAuth callback"""
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_CALLBACK_URL]
                }
            },
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
        )
        
        flow.redirect_uri = GOOGLE_CALLBACK_URL
        
        # Get authorization response
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        # Get user info
        credentials = flow.credentials
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        
        # Store user info in session
        session['user_id'] = id_info['sub']
        session['user_email'] = id_info['email']
        session['user_name'] = id_info.get('name', '')
        session['user_picture'] = id_info.get('picture', '')
        session['authenticated'] = True
        
        # Check if user already exists in MongoDB
        existing_user_data = get_user_data(id_info['sub'])
        
        if existing_user_data:
            # User exists, preserve their data
            print(f"User {id_info['sub']} already exists, preserving data")
            # Update only the basic info, keep existing accounts and groups
            existing_user_data.update({
                'email': id_info['email'],
                'name': id_info.get('name', ''),
                'picture': id_info.get('picture', '')
            })
            save_user_data(id_info['sub'], existing_user_data)
        else:
            # New user, create initial data
            print(f"Creating new user {id_info['sub']}")
            user_data = {
                'user_id': id_info['sub'],
                'email': id_info['email'],
                'name': id_info.get('name', ''),
                'picture': id_info.get('picture', ''),
                'accounts': [],
                'groups': []
            }
            save_user_data(id_info['sub'], user_data)
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"OAuth Error: {str(e)}")  # Debug logging
        return redirect(url_for('login') + f'?error={str(e)}')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/health')
def health():
    """Health check endpoint for Koyeb"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/')
def index():
    """Main application page - requires authentication"""
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    
    # Get user data from MongoDB
    user_id = session.get('user_id')
    
    user_data = get_user_data(user_id) if user_id else None
    
    # Always sync session with MongoDB data
    if user_data:
        session['user_accounts'] = user_data.get('accounts', [])
        session['user_groups'] = user_data.get('groups', [])
    else:
        # Create empty user data if none exists
        session['user_accounts'] = []
        session['user_groups'] = []
        
        # Create user data in MongoDB
        user_data = {
            'user_id': user_id,
            'email': session.get('user_email', ''),
            'name': session.get('user_name', ''),
            'picture': session.get('user_picture', ''),
            'accounts': [],
            'groups': []
        }
        save_user_data(user_id, user_data)
    
    return render_template('index.html', user=session)

if __name__ == '__main__':
    # Start the background scheduler
    start_scheduler()
    
    try:
        # Get port from environment variable (for production) or use 5000
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_ENV') == 'development'
        
        app.run(debug=debug, host='0.0.0.0', port=port) 
    finally:
        # Stop the scheduler when the app shuts down
        stop_scheduler() 
