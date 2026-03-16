"""SMTP email connector — sends compliance notifications via email."""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

from .base import BaseConnector

logger = logging.getLogger("tracemark.connectors.email")


class EmailConnector(BaseConnector):
    """Sends templated compliance emails via SMTP."""

    connector_type = "email"

    async def configure(self) -> bool:
        required = ["smtp_host", "from_address"]
        for field in required:
            if not self.config.get(field):
                logger.error(f"Email connector {self.connector_id}: missing required field '{field}'")
                return False
        self.status = "active"
        return True

    async def validate(self) -> dict:
        """Test SMTP connection."""
        try:
            result = await asyncio.to_thread(self._test_smtp)
            return result
        except Exception as e:
            return {"success": False, "message": f"SMTP connection failed: {e}"}

    def _test_smtp(self) -> dict:
        host = self.config.get("smtp_host", "")
        port = int(self.config.get("smtp_port", 587))
        try:
            server = smtplib.SMTP(host, port, timeout=10)
            server.ehlo()
            if port == 587:
                server.starttls()
            user = self.config.get("smtp_user")
            passwd = self.config.get("smtp_pass")
            if user and passwd:
                server.login(user, passwd)
            server.quit()
            return {"success": True, "message": f"SMTP connection to {host}:{port} validated"}
        except Exception as e:
            return {"success": False, "message": f"SMTP error: {e}"}

    async def execute(self, payload: dict) -> dict:
        """Send a compliance notification email."""
        result = await asyncio.to_thread(self._send_email, payload)
        return result

    def _send_email(self, payload: dict) -> dict:
        from_addr = self.config.get("from_address", "")
        to_addr = payload.get("to_address", self.config.get("to_address", ""))
        if not to_addr:
            raise ValueError("No recipient address specified")

        # Apply template variables
        subject_template = self.config.get("subject_template", "Tracemark Alert: {{violation}}")
        body_template = self.config.get("body_template",
            "Tracemark Policy Violation Alert\n\n"
            "Caller: {{caller}}\n"
            "Violation: {{violation}}\n"
            "Policy: {{policy}}\n"
            "Timestamp: {{timestamp}}\n"
            "Entry ID: {{entry_id}}\n\n"
            "Please review this incident in the Tracemark dashboard."
        )

        template_vars = {
            "caller": payload.get("caller", "unknown"),
            "violation": payload.get("violation", "Policy Violation"),
            "policy": payload.get("policy", "unknown"),
            "timestamp": payload.get("timestamp", ""),
            "entry_id": payload.get("entry_id", ""),
        }

        subject = subject_template
        body = body_template
        for key, value in template_vars.items():
            subject = subject.replace("{{" + key + "}}", str(value))
            body = body.replace("{{" + key + "}}", str(value))

        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        host = self.config.get("smtp_host", "")
        port = int(self.config.get("smtp_port", 587))

        server = smtplib.SMTP(host, port, timeout=30)
        server.ehlo()
        if port == 587:
            server.starttls()
        user = self.config.get("smtp_user")
        passwd = self.config.get("smtp_pass")
        if user and passwd:
            server.login(user, passwd)
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()

        logger.info(f"Email sent to {to_addr} re: {subject}")
        return {"action": "email_sent", "to": to_addr, "subject": subject, "status": "success"}

    async def rollback(self, execution_id: str) -> dict:
        """Email rollback requires provider-specific recall API."""
        return {
            "action": "rollback_not_available",
            "reason": "Email recall requires provider-specific API integration",
            "execution_id": execution_id,
        }
