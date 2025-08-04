# Facebook Auto-Post Deployment Guide for Koyeb

## Prerequisites

1. **Koyeb Account**: Sign up at [koyeb.com](https://koyeb.com)
2. **GitHub Repository**: Push your code to a GitHub repository
3. **Google OAuth Setup**: Configure Google OAuth for production
4. **MongoDB Atlas**: Ensure your MongoDB cluster is accessible from external IPs

## Step 1: Prepare Your Code

Your code is already prepared with the necessary files:
- `Procfile` - Tells Koyeb how to run your app
- `runtime.txt` - Specifies Python version
- `koyeb.yaml` - Koyeb configuration
- `requirements.txt` - Python dependencies
- `.gitignore` - Excludes unnecessary files

## Step 2: Update Google OAuth Configuration

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to "APIs & Services" > "Credentials"
3. Edit your OAuth 2.0 Client ID
4. Add your Koyeb domain to authorized redirect URIs:
   - `https://your-app-name.koyeb.app/auth/oauth2callback`
   - Replace `your-app-name` with your actual Koyeb app name

## Step 3: Deploy to Koyeb

### Option A: Deploy via Koyeb Dashboard

1. **Connect GitHub**:
   - Go to [Koyeb Dashboard](https://app.koyeb.com/)
   - Click "Create App"
   - Choose "GitHub" as deployment method
   - Connect your GitHub account
   - Select your repository

2. **Configure Environment Variables**:
   ```
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GOOGLE_REDIRECT_URI=https://your-app-name.koyeb.app/auth/oauth2callback
   MONGODB_URI=your_mongodb_connection_string
   SECRET_KEY=your_secret_key_here
   FLASK_ENV=production
   PORT=5000
   ```

3. **Deploy Settings**:
   - **Build Command**: Leave empty (Koyeb auto-detects Python)
   - **Run Command**: `python app.py`
   - **Port**: `5000`

### Option B: Deploy via Koyeb CLI

1. **Install Koyeb CLI**:
   ```bash
   # macOS
   brew install koyeb/tap/cli
   
   # Windows
   scoop install koyeb
   
   # Linux
   curl -fsSL https://cli.koyeb.com/install.sh | bash
   ```

2. **Login to Koyeb**:
   ```bash
   koyeb login
   ```

3. **Deploy**:
   ```bash
   koyeb app init facebook-autopost \
     --git github.com/yourusername/your-repo \
     --git-branch main \
     --ports 5000:http \
     --env GOOGLE_CLIENT_ID=your_google_client_id \
     --env GOOGLE_CLIENT_SECRET=your_google_client_secret \
     --env GOOGLE_REDIRECT_URI=https://your-app-name.koyeb.app/auth/oauth2callback \
     --env MONGODB_URI=your_mongodb_connection_string \
     --env SECRET_KEY=your_secret_key_here \
     --env FLASK_ENV=production \
     --env PORT=5000
   ```

## Step 4: Configure MongoDB Atlas

1. **Network Access**:
   - Go to MongoDB Atlas Dashboard
   - Navigate to "Network Access"
   - Add `0.0.0.0/0` to allow access from anywhere (or specific Koyeb IPs)

2. **Database User**:
   - Ensure your database user has proper permissions
   - Use the connection string in your environment variables

## Step 5: Verify Deployment

1. **Check App Status**:
   - Go to your Koyeb dashboard
   - Verify the app is running (green status)

2. **Test Authentication**:
   - Visit your app URL
   - Try logging in with Google
   - Verify redirect works correctly

3. **Check Logs**:
   - In Koyeb dashboard, go to "Logs" tab
   - Look for any errors or issues

## Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID | `981431793001-xxx.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret | `GOCSPX-xxx` |
| `GOOGLE_REDIRECT_URI` | OAuth redirect URI | `https://your-app.koyeb.app/auth/oauth2callback` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://user:pass@cluster.mongodb.net/db` |
| `SECRET_KEY` | Flask secret key | `your-secret-key-here` |
| `FLASK_ENV` | Flask environment | `production` |
| `PORT` | Application port | `5000` |

## Troubleshooting

### Common Issues

1. **OAuth Redirect Error**:
   - Ensure redirect URI matches exactly
   - Check for trailing slashes
   - Verify HTTPS protocol

2. **MongoDB Connection Error**:
   - Check network access settings
   - Verify connection string format
   - Ensure database user permissions

3. **App Not Starting**:
   - Check logs in Koyeb dashboard
   - Verify all environment variables are set
   - Check Python version compatibility

4. **Scheduler Not Working**:
   - Verify background threads are allowed
   - Check for any blocking operations
   - Review scheduler logs

### Getting Help

- **Koyeb Documentation**: [docs.koyeb.com](https://docs.koyeb.com)
- **Koyeb Support**: Available in dashboard
- **Application Logs**: Check in Koyeb dashboard under "Logs" tab

## Security Considerations

1. **Environment Variables**: Never commit secrets to Git
2. **HTTPS**: Koyeb provides automatic HTTPS
3. **Database Security**: Use strong passwords and restrict network access
4. **OAuth Security**: Keep client secrets secure
5. **Session Security**: Use strong secret keys

## Monitoring

1. **Koyeb Metrics**: Monitor CPU, memory, and request metrics
2. **Application Logs**: Check for errors and performance issues
3. **Database Monitoring**: Monitor MongoDB Atlas metrics
4. **Uptime Monitoring**: Set up external monitoring if needed

## Scaling

Your app is configured to scale from 1 to 3 instances automatically. You can adjust this in the Koyeb dashboard under "Scaling" settings. 