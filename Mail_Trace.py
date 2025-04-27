# Corsair Network Test Tool
#Mail Trace Module
# This module provides functionality to send crash reports via email using SMTP.
# It captures unhandled exceptions in Tkinter callbacks and sends the traceback to a specified email address.
# It also provides a simple GUI interface to test the email functionality.

import traceback
import smtplib
from smtplib import SMTPAuthenticationError
import sys
import io
import base64
from email.message import EmailMessage
import tkinter as tk
from tkinter import scrolledtext

# Optional OAuth2 support via MSAL
try:
    import msal
    _HAS_MSAL = True
except ImportError:
    _HAS_MSAL = False

# Configuration for SMTP and OAuth2
CONFIG = {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "your_email@domain.com",
    "pass": "your_app_password",
    # OAuth2 settings (only used if use_oauth True)
    "client_id": "YOUR_AZURE_APP_ID",
    "tenant_id": "common",
    "scopes": ["https://outlook.office365.com/SMTP.Send"],
    "use_oauth": False
}

_token_cache = None


def obtain_oauth2_token():
    if not _HAS_MSAL:
        raise RuntimeError("MSAL library not installed; cannot perform OAuth2.")
    global _token_cache
    if _token_cache is None:
        _token_cache = msal.SerializableTokenCache()
    app = msal.PublicClientApplication(
        client_id=CONFIG["client_id"],
        authority=f"https://login.microsoftonline.com/{CONFIG['tenant_id']}",
        token_cache=_token_cache
    )
    accounts = app.get_accounts()
    result = None
    if accounts:
        result = app.acquire_token_silent(CONFIG["scopes"], account=accounts[0])
    if not result:
        result = app.acquire_token_interactive(CONFIG["scopes"])
    if "access_token" in result:
        return result["access_token"]
    raise RuntimeError(f"Failed to obtain OAuth2 token: {result.get('error_description')}")


def send_error_email(tb_text: str, debug_log_callback=None):
   
    #Send the traceback via SMTP. Captures SMTP debug, and sends an email including:
    #Crash traceback
    #SMTP server host/port
    #From and To addresses
    #SMTP transaction log
   
    # Build email message
    msg = EmailMessage()
    msg["Subject"] = "Crash Report: Network Test Tool"
    from_addr = CONFIG.get("user")
    to_addr = CONFIG.get("to", from_addr)
    msg["From"] = from_addr
    msg["To"] = to_addr

    # Include header with SMTP details
    header = (
        f"SMTP Server: {CONFIG['host']}:{CONFIG['port']}\n"
        f"From: {from_addr}\n"
        f"To: {to_addr}\n\n"
    )
    # Initial body with traceback
    body = header + "A crash occurred in the tool:\n\n" + tb_text + "\n"

    # Capture SMTP debug output
    buf = io.StringIO() if debug_log_callback else None
    orig_stdout = sys.stdout
    debug_output = ""
    try:
        if buf:
            sys.stdout = buf
        smtp = smtplib.SMTP(CONFIG["host"], CONFIG["port"])
        smtp.set_debuglevel(1)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        try:
            smtp.login(CONFIG["user"], CONFIG["pass"])
        except SMTPAuthenticationError as auth_err:
            if CONFIG.get("use_oauth") and _HAS_MSAL and b"basic authentication is disabled" in auth_err.smtp_error.lower():
                token = obtain_oauth2_token()
                auth_str = f"user={from_addr}\x01auth=Bearer {token}\x01\x01"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                smtp.docmd("AUTH", f"XOAUTH2 {auth_b64}")
            else:
                raise
        smtp.send_message(msg)
        smtp.quit()
    finally:
        if buf:
            sys.stdout = orig_stdout
            debug_output = buf.getvalue()
            buf.close()
            if debug_log_callback:
                debug_log_callback(debug_output)

    # Append SMTP transaction log
    full_body = body + "\nSMTP transaction log:\n" + debug_output
    msg.set_content(full_body)

    # Send augmented email
    smtp2 = smtplib.SMTP(CONFIG["host"], CONFIG["port"])
    smtp2.starttls()
    smtp2.login(CONFIG["user"], CONFIG["pass"])
    smtp2.send_message(msg)
    smtp2.quit()


def report_callback_exception(self, exc, val, tb):
    text = ''.join(traceback.format_exception(exc, val, tb))
    print(text, file=sys.stderr)
    try:
        send_error_email(text)
    except Exception as e:
        print(f"Error sending crash email: {e}", file=sys.stderr)


def install_mail_trace():
    tk.Tk.report_callback_exception = report_callback_exception
    def decorator(main_func):
        def wrapped(*args, **kwargs):
            try:
                return main_func(*args, **kwargs)
            except Exception:
                tb = traceback.format_exc()
                print(tb, file=sys.stderr)
                send_error_email(tb)
                raise
        return wrapped
    return decorator


def create_mail_trace_tab(notebook):
    from tkinter import ttk, messagebox
    frame = ttk.Frame(notebook)
    notebook.add(frame, text="Mail Trace")

    entries = {}
    labels = ["host", "port", "user", "pass"]
    for i, key in enumerate(labels):
        ttk.Label(frame, text=f"{key}:").grid(row=i, column=0, sticky="w", padx=5, pady=2)
        var = tk.StringVar(value=str(CONFIG.get(key, '')))
        ent = ttk.Entry(frame, textvariable=var, width=40, show='*' if key=='pass' else None)
        ent.grid(row=i, column=1, padx=5, pady=2)
        entries[key] = var

    oauth_var = tk.BooleanVar(value=CONFIG.get("use_oauth", False))
    ttk.Checkbutton(frame, text="Use OAuth2", variable=oauth_var).grid(row=len(labels), column=0, columnspan=2, sticky="w", padx=5)

    log = scrolledtext.ScrolledText(frame, height=8, state='disabled')
    log.grid(row=len(labels)+1, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

    def append_log(m):
        log.config(state='normal')
        log.insert(tk.END, m+"\n")
        log.config(state='disabled')

    def save():
        for k, v in entries.items():
            CONFIG[k] = int(v.get()) if k=='port' else v.get()
        CONFIG['use_oauth'] = oauth_var.get()
        messagebox.showinfo("Mail Trace", "Settings saved.")
        append_log(f"Settings updated: server={CONFIG['host']}:{CONFIG['port']} from={CONFIG['user']} to={CONFIG.get('to', CONFIG['user'])}")
    ttk.Button(frame, text="Save Settings", command=save).grid(row=len(labels)+2, column=0, padx=5)

    def test_send():
        """Send a test crash report: show traceback in console and GUI, then email with SMTP details."""
        append_log("Sending test report...")
        # Log SMTP details
        append_log(f"Using SMTP server {CONFIG['host']}:{CONFIG['port']}")
        append_log(f"From: {CONFIG['user']}")
        append_log(f"To: {CONFIG.get('to', CONFIG['user'])}")
        tb = None
        try:
            raise RuntimeError("Test crash trigger.")
        except Exception:
            tb = traceback.format_exc()
            print(tb, file=sys.stdout)
            append_log("--- Traceback Start ---")
            for line in tb.splitlines():
                append_log(line)
            append_log("--- Traceback End ---")
        if tb:
            try:
                send_error_email(tb, debug_log_callback=append_log)
                messagebox.showinfo("Mail Trace", "Test report sent successfully.")
                append_log("Email sent successfully.")
            except Exception as e:
                messagebox.showerror("Mail Trace", f"Send error: {e}")
                append_log(f"Send error: {e}")
    ttk.Button(frame, text="Send Test Report", command=test_send).grid(row=len(labels)+2, column=1, padx=5)

    frame.grid_rowconfigure(len(labels)+1, weight=1)
    frame.grid_columnconfigure(1, weight=1)
    return frame




if __name__ == "__main__":
    
    install_mail_trace()  # patch Tk, though it won’t be used in CLI
    try:
        raise RuntimeError("This is a test exception")
    except Exception:
        import traceback
        tb = traceback.format_exc()
        send_error_email(tb)
        print("Test crash report sent (check your email).")