#!/usr/bin/env python3
"""
DragonShard Database-Backed Session Manager

Replaces the in-memory session manager with persistent database storage.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from dragonshard.data.database import get_repository
from dragonshard.data.models import AuthCredentials, AuthMethod, Session, SessionState

logger = logging.getLogger(__name__)


class DatabaseSessionManager:
    """
    Database-backed session manager for persistent storage.
    """

    def __init__(self):
        """Initialize the database session manager."""
        self.session_repo = get_repository(Session)
        self.credentials_repo = get_repository(AuthCredentials)
        self.client = httpx.Client(follow_redirects=True)

        logger.info("DatabaseSessionManager initialized successfully")

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

        session_data = {
            "session_id": session_id,
            "target_host": target_host,
            "state": SessionState.UNAUTHENTICATED,
            "auth_method": auth_method,
            "cookies": json.dumps({}),
            "headers": json.dumps({"User-Agent": "DragonShard/1.0"}),
            "created_at": time.time(),
            "last_used": time.time(),
        }

        self.session_repo.create(**session_data)
        logger.info(f"Created session {session_id} for {target_host}")

        return session_id

    def authenticate_session(self, session_id: str, credentials: Dict[str, str]) -> bool:
        """
        Authenticate a session using provided credentials.

        Args:
            session_id: The session ID
            credentials: Authentication credentials dictionary

        Returns:
            True if authentication successful, False otherwise
        """
        session = self.session_repo.get_by_id(session_id)
        if not session:
            logger.error(f"Session {session_id} not found")
            return False

        # Update last_used timestamp
        self.session_repo.update(session_id, last_used=time.time())

        try:
            if session.auth_method == AuthMethod.FORM:
                success = self._authenticate_form(session, credentials)
            elif session.auth_method == AuthMethod.BASIC:
                success = self._authenticate_basic(session, credentials)
            elif session.auth_method == AuthMethod.TOKEN:
                success = self._authenticate_token(session, credentials)
            else:
                # No authentication required
                self.session_repo.update(session_id, state=SessionState.AUTHENTICATED)
                success = True

            if success:
                # Store credentials
                self.credentials_repo.create(
                    session_id=session_id,
                    username=credentials.get("username", ""),
                    password=credentials.get("password", ""),
                    token=credentials.get("token"),
                    api_key=credentials.get("api_key"),
                )
                logger.info(f"Session {session_id} authenticated successfully")
            else:
                self.session_repo.update(session_id, state=SessionState.ERROR)
                logger.error(f"Authentication failed for session {session_id}")

            return success

        except Exception as e:
            self.session_repo.update(session_id, state=SessionState.ERROR)
            logger.error(f"Authentication error for session {session_id}: {e}")
            return False

    def _authenticate_form(self, session: Session, credentials: Dict[str, str]) -> bool:
        """Authenticate using form-based authentication."""
        try:
            # Try to find login form
            login_url = session.login_url or f"{session.target_host}/login"

            # Get the login page to extract CSRF token
            response = self.client.get(login_url)

            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(response.text)
            if csrf_token:
                self.session_repo.update(session.session_id, csrf_token=csrf_token)

            # Prepare login data
            login_data = {
                "username": credentials.get("username", ""),
                "password": credentials.get("password", ""),
            }

            if csrf_token:
                login_data["csrf_token"] = csrf_token

            # Submit login form
            response = self.client.post(login_url, data=login_data)

            # Check if login was successful
            if response.status_code == 200 and "login" not in response.text.lower():
                # Extract cookies from response
                cookies = {}
                for cookie in response.cookies:
                    cookies[cookie.name] = cookie.value

                # Update session
                self.session_repo.update(
                    session.session_id,
                    state=SessionState.AUTHENTICATED,
                    cookies=json.dumps(cookies),
                    last_used=time.time(),
                )
                return True
            else:
                self.session_repo.update(session.session_id, state=SessionState.ERROR)
                return False

        except Exception as e:
            logger.error(f"Form authentication error: {e}")
            return False

    def _authenticate_basic(self, session: Session, credentials: Dict[str, str]) -> bool:
        """Authenticate using HTTP Basic authentication."""
        try:
            from requests.auth import HTTPBasicAuth

            response = self.client.get(
                session.target_host,
                auth=HTTPBasicAuth(credentials.get("username", ""), credentials.get("password", "")),
            )

            if response.status_code == 200:
                self.session_repo.update(
                    session.session_id,
                    state=SessionState.AUTHENTICATED,
                    last_used=time.time(),
                )
                return True
            else:
                self.session_repo.update(session.session_id, state=SessionState.ERROR)
                return False

        except Exception as e:
            logger.error(f"Basic authentication error: {e}")
            return False

    def _authenticate_token(self, session: Session, credentials: Dict[str, str]) -> bool:
        """Authenticate using token-based authentication."""
        try:
            token = credentials.get("token")
            if not token:
                logger.error("No token provided for token authentication")
                return False

            # Add token to headers
            headers = json.loads(session.headers)
            headers["Authorization"] = f"Bearer {token}"

            # Test the token
            response = self.client.get(session.target_host, headers=headers)

            if response.status_code == 200:
                self.session_repo.update(
                    session.session_id,
                    state=SessionState.AUTHENTICATED,
                    headers=json.dumps(headers),
                    last_used=time.time(),
                )
                return True
            else:
                self.session_repo.update(session.session_id, state=SessionState.ERROR)
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
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
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
        session = self.session_repo.get_by_id(session_id)
        if not session:
            return {}

        # Update last_used timestamp
        self.session_repo.update(session_id, last_used=time.time())

        headers = json.loads(session.headers)

        # Add cookies as headers if needed
        cookies = json.loads(session.cookies)
        if cookies:
            cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
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
        session = self.session_repo.get_by_id(session_id)
        if not session:
            return {}

        # Update last_used timestamp
        self.session_repo.update(session_id, last_used=time.time())

        return json.loads(session.cookies)

    def update_session_cookies(self, session_id: str, cookies: Dict[str, str]) -> None:
        """
        Update session cookies.

        Args:
            session_id: The session ID
            cookies: New cookies to add/update
        """
        session = self.session_repo.get_by_id(session_id)
        if not session:
            return

        current_cookies = json.loads(session.cookies)
        current_cookies.update(cookies)

        self.session_repo.update(
            session_id,
            cookies=json.dumps(current_cookies),
            last_used=time.time(),
        )

    def check_session_validity(self, session_id: str) -> bool:
        """
        Check if a session is still valid.

        Args:
            session_id: The session ID

        Returns:
            True if session is valid, False otherwise
        """
        session = self.session_repo.get_by_id(session_id)
        if not session:
            return False

        # Check if session has expired
        if session.expires_at and time.time() > session.expires_at:
            self.session_repo.update(session_id, state=SessionState.EXPIRED)
            return False

        # Check if session is authenticated
        if session.state != SessionState.AUTHENTICATED:
            return False

        # Check if session hasn't been used for too long (optional)
        if time.time() - session.last_used > 3600:  # 1 hour
            self.session_repo.update(session_id, state=SessionState.EXPIRED)
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
        session = self.session_repo.get_by_id(session_id)
        if not session:
            return False

        try:
            if session.logout_url:
                # Try to logout properly
                response = self.client.post(session.logout_url)
                if response.status_code == 200:
                    logger.info(f"Logged out from session {session_id}")

            # Clear session data
            self.session_repo.update(
                session_id,
                state=SessionState.UNAUTHENTICATED,
                cookies=json.dumps({}),
                headers=json.dumps({"User-Agent": session.user_agent}),
            )

            # Remove credentials
            credentials = self.credentials_repo.filter_by(session_id=session_id)
            for cred in credentials:
                self.credentials_repo.delete(cred.id)

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
        # Logout first
        self.logout_session(session_id)

        # Remove session
        success = self.session_repo.delete(session_id)

        if success:
            logger.info(f"Destroyed session {session_id}")
        return success

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a session.

        Args:
            session_id: The session ID

        Returns:
            Session information dictionary
        """
        session = self.session_repo.get_by_id(session_id)
        if not session:
            return None

        return {
            "session_id": session.session_id,
            "target_host": session.target_host,
            "state": session.state.value,
            "auth_method": session.auth_method.value,
            "created_at": session.created_at,
            "last_used": session.last_used,
            "expires_at": session.expires_at,
            "cookie_count": len(json.loads(session.cookies)),
            "header_count": len(json.loads(session.headers)),
        }

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """
        Get information about all sessions.

        Returns:
            List of session information dictionaries
        """
        sessions = self.session_repo.get_all()
        return [self.get_session_info(session.session_id) for session in sessions]

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        current_time = time.time()
        expired_sessions = []

        # Find expired sessions
        sessions = self.session_repo.get_all()
        for session in sessions:
            if session.expires_at and current_time > session.expires_at:
                expired_sessions.append(session.session_id)
            elif current_time - session.last_used > 7200:  # 2 hours
                expired_sessions.append(session.session_id)

        # Destroy expired sessions
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
        sessions = self.session_repo.get_all()
        credentials = self.credentials_repo.get_all()

        data = {
            "exported_at": time.time(),
            "sessions": [session.to_dict() for session in sessions],
            "credentials": [cred.to_dict() for cred in credentials],
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
                self.session_repo.create(**session_data)

            # Import credentials
            for cred_data in data.get("credentials", []):
                self.credentials_repo.create(**cred_data)

            logger.info(f"Imported {len(data.get('sessions', []))} sessions from {filename}")
            return True

        except Exception as e:
            logger.error(f"Failed to import sessions from {filename}: {e}")
            return False 