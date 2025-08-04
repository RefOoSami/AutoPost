# Facebook Auto-Post - Koyeb Deployment

## Quick Deploy

1. **Push to GitHub**: Upload your code to a GitHub repository
2. **Deploy to Koyeb**: Use the Koyeb dashboard or CLI to deploy
3. **Set Environment Variables**: Configure all required environment variables
4. **Update OAuth**: Add your Koyeb domain to Google OAuth redirect URIs

## Required Environment Variables

```bash
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=https://your-app-name.koyeb.app/auth/oauth2callback
MONGODB_URI=your_mongodb_connection_string
SECRET_KEY=your_secret_key_here
FLASK_ENV=production
PORT=5000
```

## Files Created for Deployment

- `Procfile` - Tells Koyeb how to run the app
- `runtime.txt` - Python version specification
- `koyeb.yaml` - Koyeb configuration
- `requirements.txt` - Updated with gunicorn
- `.gitignore` - Excludes unnecessary files
- `start.sh` - Startup script
- `DEPLOYMENT.md` - Detailed deployment guide

## Health Check

The app includes a health check endpoint at `/health` for Koyeb monitoring.

## Support

For detailed deployment instructions, see `DEPLOYMENT.md`. 