"""
Mail_Trace.py
-------------
Module to capture uncaught exceptions (including Tkinter callback errors)
and automatically email full tracebacks to a configured address.

Provides:
 - send_error_email(tb_text): send traceback via SMTP
 - report_callback_exception: override for Tkinter exception handling
 - install_mail_trace(): patch Tkinter and optionally wrap main()
 - create_mail_trace_tab(notebook): stub for adding a "Mail Trace" UI tab
"""

import traceback
import smtplib
import sys
from email.message import EmailMessage
import tkinter as tk

# --- SMTP CONFIGURATION: Replace placeholders with actual credentials ---
SMTP_HOST    = "smtp.yourmail.com"
SMTP_PORT    = 587
SMTP_USER    = "your_smtp_user"
SMTP_PASS    = "your_smtp_password"
FROM_ADDRESS = "tool@yourdomain.com"
TO_ADDRESS   = "you@yourdomain.com"
# ----------------------------------------------------------------------


def send_error_email(tb_text: str):
    """
    Send the given traceback text in an email via the configured SMTP server.
    """
    msg = EmailMessage()
    msg["Subject"] = "Corsair Network Test Tool Crash Report"
    msg["From"]    = FROM_ADDRESS
    msg["To"]      = TO_ADDRESS
    msg.set_content(f"A crash occurred in the Network Test Tool:\n\n{tb_text}")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


def report_callback_exception(self, exc, val, tb):
    """
    Override for Tk.report_callback_exception so that any uncaught exception
    in a Tkinter callback is captured, printed, and emailed.
    """
    tb_text = ''.join(traceback.format_exception(exc, val, tb))
    # Print locally to stderr
    print("Unhandled exception in Tkinter callback:", file=sys.stderr)
    print(tb_text, file=sys.stderr)
    # Attempt to email the traceback
    try:
        send_error_email(tb_text)
    except Exception as e:
        print(f"Failed to send crash report email: {e}", file=sys.stderr)


def install_mail_trace():
    """
    Monkey-patch Tkinter so that all widget callbacks use our exception reporter.
    Returns a decorator to wrap your main() function if you want top-level exception capturing as well.
    Call this before creating any tk.Tk() instance.
    """
    # Patch Tkinter callback exception hook
    tk.Tk.report_callback_exception = report_callback_exception

    # Decorator for wrapping the main() function
    def main_wrapper(func):
        def wrapped(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception:
                tb_text = traceback.format_exc()
                # Print and email
                print("Exception in main:", file=sys.stderr)
                print(tb_text, file=sys.stderr)
                try:
                    send_error_email(tb_text)
                except Exception as e:
                    print(f"Failed to email top-level crash report: {e}", file=sys.stderr)
                # Re-raise to allow default behavior if desired
                raise
        return wrapped

    return main_wrapper


def create_mail_trace_tab(notebook):
    """
    Stub for UI wiring: adds an empty "Mail Trace" tab to the given Notebook.
    Import and call this from your main script after setting up install_mail_trace().
    """
    from tkinter import ttk

    frame = ttk.Frame(notebook)
    notebook.add(frame, text="Mail Trace")
    # Example placeholder content:
    # ttk.Label(frame, text="Crash reports will be emailed automatically.").pack(padx=10, pady=10)
    return frame
if __name__ == "__main__":
    # This will just send a dummy “test” crash report
    install_mail_trace()  # patch Tk, though it won’t be used in CLI
    try:
        raise RuntimeError("This is a test exception")
    except Exception:
        import traceback
        tb = traceback.format_exc()
        send_error_email(tb)
        print("Test crash report sent (check your email).")