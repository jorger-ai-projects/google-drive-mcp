// Main authentication module that re-exports and orchestrates the modular components
import { initializeOAuth2Client } from './auth/client.js';
import { AuthServer } from './auth/server.js';
import { TokenManager } from './auth/tokenManager.js';
import { GoogleAuth } from 'google-auth-library';
import { readFile } from 'fs/promises';

export { TokenManager } from './auth/tokenManager.js';
export { initializeOAuth2Client } from './auth/client.js';
export { AuthServer } from './auth/server.js';

const SA_SCOPES = [
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/drive.readonly',
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/presentations',
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/calendar.events'
];

function validateSACredentials(json: any, envVarName: string): void {
  if (json.type !== 'service_account') {
    console.error(
      `${envVarName}: expected service account credentials (type: "service_account"), ` +
      `got "${json.type ?? 'no type field'}". ` +
      `Use a service account key JSON, not an OAuth2 client credentials file.`
    );
    process.exit(1);
  }
  const missing = ['client_email', 'private_key'].filter((f) => !json[f]);
  if (missing.length > 0) {
    console.error(
      `${envVarName}: service account JSON is missing required field(s): ${missing.join(', ')}`
    );
    process.exit(1);
  }
}

async function authenticateSA(b64Config: string, keyFilePath: string): Promise<GoogleAuth> {
  // Priority 1: base64-encoded JSON (GOOGLE_DRIVE_CREDENTIALS_CONFIG)
  if (b64Config && b64Config.trim() !== '') {
    let decoded: string;
    try {
      decoded = Buffer.from(b64Config, 'base64').toString('utf-8');
    } catch {
      console.error('GOOGLE_DRIVE_CREDENTIALS_CONFIG: base64 decode failed.');
      process.exit(1);
    }
    let credentials: any;
    try {
      credentials = JSON.parse(decoded!);
    } catch {
      console.error('GOOGLE_DRIVE_CREDENTIALS_CONFIG: decoded value is not valid JSON.');
      process.exit(1);
    }
    validateSACredentials(credentials!, 'GOOGLE_DRIVE_CREDENTIALS_CONFIG');
    console.error(`Auth method: service account (base64) — ${credentials!.client_email}`);
    return new GoogleAuth({ credentials: credentials!, scopes: SA_SCOPES });
  }

  // Priority 2: key file path (GOOGLE_DRIVE_SERVICE_ACCOUNT_PATH)
  let fileContent: string;
  try {
    fileContent = await readFile(keyFilePath, 'utf-8');
  } catch {
    console.error(
      `GOOGLE_DRIVE_SERVICE_ACCOUNT_PATH: cannot read file at "${keyFilePath}". ` +
      `Check that the file exists and is readable.`
    );
    process.exit(1);
  }
  let credentials: any;
  try {
    credentials = JSON.parse(fileContent!);
  } catch {
    console.error(
      `GOOGLE_DRIVE_SERVICE_ACCOUNT_PATH: file at "${keyFilePath}" is not valid JSON.`
    );
    process.exit(1);
  }
  validateSACredentials(credentials!, 'GOOGLE_DRIVE_SERVICE_ACCOUNT_PATH');
  console.error(`Auth method: service account (key file) — ${credentials!.client_email}`);
  return new GoogleAuth({ credentials: credentials!, scopes: SA_SCOPES });
}

/**
 * Authenticate and return OAuth2 client
 * This is the main entry point for authentication in the MCP server
 */
export async function authenticate(): Promise<any> {
  console.error('Initializing authentication...');
  
  // Initialize OAuth2 client
  const oauth2Client = await initializeOAuth2Client();
  const tokenManager = new TokenManager(oauth2Client);
  
  // Try to validate existing tokens
  if (await tokenManager.validateTokens()) {
    console.error('Authentication successful - using existing tokens');
    console.error('OAuth2Client credentials:', {
      hasAccessToken: !!oauth2Client.credentials?.access_token,
      hasRefreshToken: !!oauth2Client.credentials?.refresh_token,
      expiryDate: oauth2Client.credentials?.expiry_date
    });
    return oauth2Client;
  }
  
  // No valid tokens, need to authenticate
  console.error('\n🔐 No valid authentication tokens found.');
  console.error('Starting authentication flow...\n');
  
  const authServer = new AuthServer(oauth2Client);
  const authSuccess = await authServer.start(true);
  
  if (!authSuccess) {
    throw new Error('Authentication failed. Please check your credentials and try again.');
  }
  
  // Wait for authentication to complete
  await new Promise<void>((resolve) => {
    const checkInterval = setInterval(async () => {
      if (authServer.authCompletedSuccessfully) {
        clearInterval(checkInterval);
        await authServer.stop();
        resolve();
      }
    }, 1000);
  });
  
  return oauth2Client;
}

/**
 * Manual authentication command
 * Used when running "npm run auth" or when the user needs to re-authenticate
 */
export async function runAuthCommand(): Promise<void> {
  try {
    console.error('Google Drive MCP - Manual Authentication');
    console.error('════════════════════════════════════════\n');
    
    // Initialize OAuth client
    const oauth2Client = await initializeOAuth2Client();
    
    // Create and start the auth server
    const authServer = new AuthServer(oauth2Client);
    
    // Start with browser opening (true by default)
    const success = await authServer.start(true);
    
    if (!success && !authServer.authCompletedSuccessfully) {
      // Failed to start and tokens weren't already valid
      console.error(
        "Authentication failed. Could not start server or validate existing tokens. Check port availability (3000-3004) and try again."
      );
      process.exit(1);
    } else if (authServer.authCompletedSuccessfully) {
      // Auth was successful (either existing tokens were valid or flow completed just now)
      console.error("\n✅ Authentication successful!");
      console.error("You can now use the Google Drive MCP server.");
      process.exit(0); // Exit cleanly if auth is already done
    }
    
    // If we reach here, the server started and is waiting for the browser callback
    console.error(
      "Authentication server started. Please complete the authentication in your browser..."
    );
    
    // Wait for completion
    const intervalId = setInterval(async () => {
      if (authServer.authCompletedSuccessfully) {
        clearInterval(intervalId);
        await authServer.stop();
        console.error("\n✅ Authentication completed successfully!");
        console.error("You can now use the Google Drive MCP server.");
        process.exit(0);
      }
    }, 1000);
  } catch (error) {
    console.error("\n❌ Authentication failed:", error);
    process.exit(1);
  }
}