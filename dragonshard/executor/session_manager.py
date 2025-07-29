#!/usr/bin/env python3
"""
DragonShard Session Manager Module

Manages authentication, cookies, and session state for attack execution.
"""

import json
import logging
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session states."""
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    LOCKED = "locked"
    ERROR = "error"


class AuthMethod(Enum):
    """Authentication methods."""
    NONE = "none"
    BASIC = "basic"
    FORM = "form"
    TOKEN = "token"
    COOKIE = "cookie"
    OAUTH = "oauth"


@dataclass
class AuthCredentials:
    """Authentication credentials."""
    username: str
    password: str
    token: Optional[str] = None
    api_key: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class SessionData:
    """Session data and state."""
    session_id: str
    target_host: str
    state: SessionState
    auth_method: AuthMethod
    cookies: Dict[str, str]
    headers: Dict[str, str]
    created_at: float
    last_used: float
    expires_at: Optional[float] = None
    login_url: Optional[str] = None
    logout_url: Optional[str] = None
    csrf_token: Optional[str] = None
    user_agent: str = "DragonShard/1.0"
    proxy: Optional[str] = None


class SessionManager:
    """
    Manages authentication sessions and state for attack execution.
    """

    def __init__(self):
        """Initialize the session manager."""
        self.sessions: Dict[str, SessionData] = {}
        self.credentials: Dict[str, AuthCredentials] = {}
        self.client = httpx.Client(follow_redirects=True)
        
        logger.info("SessionManager initialized successfully")

    def create_session(self, target_host: str, auth_method: AuthMethod = AuthMethod.NONE) -> str:
        """
        Create a new session for a target host.

        Args:
            target_host: The target host
            auth_method: Authentication method to use

        Returns:
            Session ID
        """
        session_id = f"session_{int(time.time())}_{hash(target_host)}"
        
        session = SessionData(
            session_id=session_id,
            target_host=target_host,
            state=SessionState.UNAUTHENTICATED,
            auth_method=auth_method,
            cookies={},
            headers={"User-Agent": "DragonShard/1.0"},
            created_at=time.time(),
            last_used=time.time()
        )
        
        self.sessions[session_id] = session
        logger.info(f"Created session {session_id} for {target_host}")
        
        return session_id

    def authenticate_session(self, session_id: str, credentials: AuthCredentials) -> bool:
        """
        Authenticate a session using provided credentials.

        Args:
            session_id: The session ID
            credentials: Authentication credentials

        Returns:
            True if authentication successful, False otherwise
        """
        if session_id not in self.sessions:
            logger.error(f"Session {session_id} not found")
            return False
        
        session = self.sessions[session_id]
        session.last_used = time.time()
        
        try:
            if session.auth_method == AuthMethod.FORM:
                success = self._authenticate_form(session, credentials)
            elif session.auth_method == AuthMethod.BASIC:
                success = self._authenticate_basic(session, credentials)
            elif session.auth_method == AuthMethod.TOKEN:
                success = self._authenticate_token(session, credentials)
            else:
                # No authentication required
                session.state = SessionState.AUTHENTICATED
                success = True
            
            if success:
                self.credentials[session_id] = credentials
                logger.info(f"Session {session_id} authenticated successfully")
            else:
                session.state = SessionState.ERROR
                logger.error(f"Authentication failed for session {session_id}")
            
            return success
            
        except Exception as e:
            session.state = SessionState.ERROR
            logger.error(f"Authentication error for session {session_id}: {e}")
            return False

    def _authenticate_form(self, session: SessionData, credentials: AuthCredentials) -> bool:
        """Authenticate using form-based authentication."""
        try:
            # Try to find login form
            login_url = session.login_url or f"{session.target_host}/login"
            
            # Get the login page to extract CSRF token
            response = self.client.get(login_url)
            
            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(response.text)
            if csrf_token:
                session.csrf_token = csrf_token
            
            # Prepare login data
            login_data = {
                "username": credentials.username,
                "password": credentials.password
            }
            
            if csrf_token:
                login_data["csrf_token"] = csrf_token
            
            # Submit login form
            response = self.client.post(login_url, data=login_data)
            
            # Check if login was successful
            if response.status_code == 200 and "login" not in response.text.lower():
                # Extract cookies from response
                for cookie in response.cookies:
                    session.cookies[cookie.name] = cookie.value
                
                session.state = SessionState.AUTHENTICATED
                session.last_used = time.time()
                return True
            else:
                session.state = SessionState.ERROR
                return False
                
        except Exception as e:
            logger.error(f"Form authentication error: {e}")
            return False

    def _authenticate_basic(self, session: SessionData, credentials: AuthCredentials) -> bool:
        """Authenticate using HTTP Basic authentication."""
        try:
            from requests.auth import HTTPBasicAuth
            
            response = self.client.get(
                session.target_host,
                auth=HTTPBasicAuth(credentials.username, credentials.password)
            )
            
            if response.status_code == 200:
                session.state = SessionState.AUTHENTICATED
                session.last_used = time.time()
                return True
            else:
                session.state = SessionState.ERROR
                return False
                
        except Exception as e:
            logger.error(f"Basic authentication error: {e}")
            return False

    def _authenticate_token(self, session: SessionData, credentials: AuthCredentials) -> bool:
        """Authenticate using token-based authentication."""
        try:
            if not credentials.token:
                logger.error("No token provided for token authentication")
                return False
            
            # Add token to headers
            session.headers["Authorization"] = f"Bearer {credentials.token}"
            
            # Test the token
            response = self.client.get(session.target_host, headers=session.headers)
            
            if response.status_code == 200:
                session.state = SessionState.AUTHENTICATED
                session.last_used = time.time()
                return True
            else:
                session.state = SessionState.ERROR
                return False
                
        except Exception as e:
            logger.error(f"Token authentication error: {e}")
            return False

    def _extract_csrf_token(self, html_content: str) -> Optional[str]:
        """Extract CSRF token from HTML content."""
        import re
        
        # Common CSRF token patterns
        patterns = [
            r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def get_session_headers(self, session_id: str) -> Dict[str, str]:
        """
        Get headers for a session.

        Args:
            session_id: The session ID

        Returns:
            Dictionary of headers
        """
        if session_id not in self.sessions:
            return {}
        
        session = self.sessions[session_id]
        session.last_used = time.time()
        
        headers = session.headers.copy()
        
        # Add cookies as headers if needed
        if session.cookies:
            cookie_string = "; ".join([f"{k}={v}" for k, v in session.cookies.items()])
            headers["Cookie"] = cookie_string
        
        return headers

    def get_session_cookies(self, session_id: str) -> Dict[str, str]:
        """
        Get cookies for a session.

        Args:
            session_id: The session ID

        Returns:
            Dictionary of cookies
        """
        if session_id not in self.sessions:
            return {}
        
        session = self.sessions[session_id]
        session.last_used = time.time()
        
        return session.cookies.copy()

    def update_session_cookies(self, session_id: str, cookies: Dict[str, str]) -> None:
        """
        Update session cookies.

        Args:
            session_id: The session ID
            cookies: New cookies to add/update
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        session.cookies.update(cookies)
        session.last_used = time.time()

    def check_session_validity(self, session_id: str) -> bool:
        """
        Check if a session is still valid.

        Args:
            session_id: The session ID

        Returns:
            True if session is valid, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Check if session has expired
        if session.expires_at and time.time() > session.expires_at:
            session.state = SessionState.EXPIRED
            return False
        
        # Check if session is authenticated
        if session.state != SessionState.AUTHENTICATED:
            return False
        
        # Check if session hasn't been used for too long (optional)
        if time.time() - session.last_used > 3600:  # 1 hour
            session.state = SessionState.EXPIRED
            return False
        
        return True

    def logout_session(self, session_id: str) -> bool:
        """
        Logout from a session.

        Args:
            session_id: The session ID

        Returns:
            True if logout successful, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        try:
            if session.logout_url:
                # Try to logout properly
                response = self.client.post(session.logout_url)
                if response.status_code == 200:
                    logger.info(f"Logged out from session {session_id}")
            
            # Clear session data
            session.state = SessionState.UNAUTHENTICATED
            session.cookies.clear()
            session.headers = {"User-Agent": session.user_agent}
            
            # Remove credentials
            if session_id in self.credentials:
                del self.credentials[session_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Logout error for session {session_id}: {e}")
            return False

    def destroy_session(self, session_id: str) -> bool:
        """
        Destroy a session completely.

        Args:
            session_id: The session ID

        Returns:
            True if session destroyed, False otherwise
        """
        if session_id not in self.sessions:
            return False
        
        # Logout first
        self.logout_session(session_id)
        
        # Remove session
        del self.sessions[session_id]
        
        logger.info(f"Destroyed session {session_id}")
        return True

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a session.

        Args:
            session_id: The session ID

        Returns:
            Session information dictionary
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        return {
            "session_id": session.session_id,
            "target_host": session.target_host,
            "state": session.state.value,
            "auth_method": session.auth_method.value,
            "created_at": session.created_at,
            "last_used": session.last_used,
            "expires_at": session.expires_at,
            "cookie_count": len(session.cookies),
            "header_count": len(session.headers)
        }

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """
        Get information about all sessions.

        Returns:
            List of session information dictionaries
        """
        return [self.get_session_info(sid) for sid in self.sessions.keys()]

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if session.expires_at and time.time() > session.expires_at:
                expired_sessions.append(session_id)
            elif time.time() - session.last_used > 7200:  # 2 hours
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.destroy_session(session_id)
        
        logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        return len(expired_sessions)

    def export_sessions(self, filename: str) -> None:
        """
        Export session data to a JSON file.

        Args:
            filename: Output filename
        """
        def convert_enum(obj):
            """Convert Enum values to strings for JSON serialization."""
            if isinstance(obj, dict):
                return {k: convert_enum(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enum(item) for item in obj]
            elif hasattr(obj, 'value'):  # Enum objects
                return obj.value
            else:
                return obj
        
        data = {
            "exported_at": time.time(),
            "sessions": [convert_enum(asdict(session)) for session in self.sessions.values()],
            "credentials": {
                sid: {
                    "username": cred.username,
                    "has_password": bool(cred.password),
                    "has_token": bool(cred.token),
                    "has_api_key": bool(cred.api_key)
                }
                for sid, cred in self.credentials.items()
            }
        }
        
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported session data to {filename}")

    def import_sessions(self, filename: str) -> bool:
        """
        Import session data from a JSON file.

        Args:
            filename: Input filename

        Returns:
            True if import successful, False otherwise
        """
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            
            # Import sessions
            for session_data in data.get("sessions", []):
                session = SessionData(**session_data)
                self.sessions[session.session_id] = session
            
            logger.info(f"Imported {len(data.get('sessions', []))} sessions from {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import sessions from {filename}: {e}")
            return False


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)

    # Initialize session manager
    session_manager = SessionManager()

    # Create a session
    session_id = session_manager.create_session("http://example.com", AuthMethod.FORM)

    # Set up credentials
    credentials = AuthCredentials(
        username="admin",
        password="password123"
    )

    # Authenticate (this would normally be done with real credentials)
    print(f"Session created: {session_id}")
    print(f"Session info: {session_manager.get_session_info(session_id)}")

    # Get session headers
    headers = session_manager.get_session_headers(session_id)
    print(f"Session headers: {headers}")

    # Cleanup
    session_manager.destroy_session(session_id)
    print("Session destroyed")
