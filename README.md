# Facebook Auto Post Tool

A Flask web application that allows you to automatically post to Facebook groups with images and captions.

## Features

- ✅ Upload multiple images with optional captions
- ✅ Main post caption
- ✅ Facebook Group posting
- ✅ Cookie-based authentication
- ✅ Modern web interface
- ✅ Real-time image previews
- ✅ Error handling and success messages

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

The application will be available at `http://localhost:5000`

## How to Use

### 1. Get Facebook Cookies

1. Open Facebook in your browser
2. Press `F12` to open Developer Tools
3. Go to the **Application** or **Storage** tab
4. Click on **Cookies** → **https://www.facebook.com**
5. Copy all cookies in the format: `name=value` (one per line)

Example cookies format:

```
sb=H0FhaEbDBXqDofWwO7rHaTA0
datr=80ZhaAM6QFIGPtBN8Y1TYIpb
c_user=100010218577436
ps_l=1
ps_n=1
dpr=1.25
fr=1tS4abHa2RFXeoAu1.AWeSFzv9_wqfJDXUnh4aWsP0NMnAAWMXS0HNpK-6_2KBv5GpbfU.Boj22N..AAA.0.0.Boj22N.AWdA20l7c2zis0ma6Q6IUtb6bQ8
xs=16%3A7Hy4FY4UTrlCCg%3A2%3A1751205947%3A-1%3A-1%3A%3AAcXXBYUMOKpYgulzP8YpmyvATnf65oD0doPtzIMHbN8
presence=C%7B%22t3%22%3A%5B%5D%2C%22utc3%22%3A1754230161513%2C%22v%22%3A1%7D
wd=1036x695
```

### 2. Get Facebook Group ID

1. Go to the Facebook group you want to post to
2. Look at the URL: `https://www.facebook.com/groups/253583927080658`
3. The Group ID is the number after `/groups/` (e.g., `253583927080658`)

### 3. Use the Web Interface

1. **Group ID**: Enter the Facebook Group ID
2. **Main Caption**: Write your main post caption
3. **Facebook Cookies**: Paste your cookies (one per line, format: name=value)
4. **Upload Images**: Select one or more images (optional)
5. **Image Captions**: Add optional captions for each image
6. **Create Post**: Click the button to create your post

## File Structure

```
autoPost/
├── app.py                 # Main Flask application
├── autoPost.py           # Original script
├── uploadImages.py       # Image upload functions
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── templates/
│   └── index.html       # Web interface template
└── uploads/             # Temporary upload folder
```

## Security Notes

- ⚠️ **Never share your Facebook cookies** - they contain your login session
- ⚠️ **Use on trusted networks** - cookies are sensitive data
- ⚠️ **Change the secret key** in `app.py` for production use
- ⚠️ **This tool is for educational purposes** - use responsibly

## Troubleshooting

### Common Issues

1. **"Failed to extract Facebook data"**

   - Check that your cookies are valid and not expired
   - Make sure you're logged into Facebook
   - Verify the Group ID is correct

2. **"Error uploading images"**

   - Check that images are in supported formats (PNG, JPG, JPEG, GIF, BMP)
   - Ensure images are not too large
   - Verify you have permission to post in the group

3. **"Post not appearing"**
   - Check if the group has posting restrictions
   - Verify your account has posting permissions
   - Wait a few minutes - posts may take time to appear

### Getting Help

If you encounter issues:

1. Check the browser console for JavaScript errors
2. Look at the Flask application logs
3. Verify all form fields are filled correctly
4. Ensure your Facebook session is active

## License

This project is for educational purposes only. Use responsibly and in accordance with Facebook's Terms of Service.
