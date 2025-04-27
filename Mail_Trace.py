# Corsair Network Test Tool
#Mail Trace Module
# This module provides functionality to send crash reports via email using SMTP.
# It captures unhandled exceptions in Tkinter callbacks and sends the traceback to a specified email address.
# It also provides a simple GUI interface to test the email functionality.

import logging
from logging.handlers import SMTPHandler
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext
import smtplib, io

# --------------------------------------------------
# Default SMTP configuration; will be overridden via GUI
CONFIG = {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "coonta75@gmail.com",
    "pass": "kxyy pjfw ngai igxc",
    "to":   ["coonta75@gmail.com"],
}
# --------------------------------------------------

# Custom SMTPHandler that captures the SMTP protocol trace
class TracingSMTPHandler(SMTPHandler):
    def emit(self, record):
        try:
            debug_buf = io.StringIO()
            port = self.mailport or smtplib.SMTP_PORT
            smtp = smtplib.SMTP(self.mailhost, port, timeout=self.timeout)
            smtp.set_debuglevel(1)

            # capture *all* debug args into our buffer
            def capture_debug(*args):
                debug_buf.write(" ".join(str(a) for a in args) + "\n")
            smtp._print_debug = capture_debug

            # perform handshake and authentication
            if self.username:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self.username, self.password)

            # format the log record (includes traceback)
            msg = self.format(record)
            full_msg = msg + "\n\n--- SMTP TRACE ---\n" + debug_buf.getvalue()

            # send email and store debug trace
            smtp.sendmail(self.fromaddr, self.toaddrs, full_msg)
            smtp.quit()
            self.debug_trace = debug_buf.getvalue()
        except Exception:
            self.handleError(record)

# Logger setup
logger = logging.getLogger("MailTrace")
logger.setLevel(logging.ERROR)
logger.propagate = False

# Factory to create our tracing handler
def make_smtp_handler():
    handler = TracingSMTPHandler(
        mailhost=(CONFIG["host"], CONFIG["port"]),
        fromaddr=CONFIG["user"],
        toaddrs=CONFIG["to"],
        subject="Crash Report: Network Test Tool",
        credentials=(CONFIG["user"], CONFIG["pass"]),
        secure=(),  # use STARTTLS
    )
    fmt = logging.Formatter(
        "%(asctime)s\n"
        "%(name)s %(levelname)s\n\n"
        "%(message)s"
    )
    handler.setFormatter(fmt)
    return handler

# Attach initial handler
smtp_handler = make_smtp_handler()
logger.addHandler(smtp_handler)

# Hook uncaught Tkinter exceptions to our logger
def report_callback_exception(self, exc, val, tb):
    logger.exception("Unhandled exception in Tkinter callback", exc_info=(exc, val, tb))
    # console printing removed to avoid clutter

# Call before tk.Tk() to install the hook
def install_mail_trace():
    tk.Tk.report_callback_exception = report_callback_exception
    return lambda f: f  # decorator no-op

# Create the Mail Trace tab in the notebook
def create_mail_trace_tab(notebook):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text="Mail Trace")

    # SMTP settings fields
    entries = {}
    for i, key in enumerate(["host", "port", "user", "pass"]):
        ttk.Label(frame, text=f"{key.capitalize()}:").grid(row=i, column=0, sticky="w", padx=5, pady=2)
        var = tk.StringVar(value=str(CONFIG[key]))
        ent = ttk.Entry(frame, textvariable=var, width=40,
                        show='*' if key=='pass' else None)
        ent.grid(row=i, column=1, padx=5, pady=2)
        entries[key] = var
    # Recipients list
    ttk.Label(frame, text="Recipients (comma-separated):").grid(row=4, column=0, sticky="w", padx=5, pady=2)
    to_var = tk.StringVar(value=','.join(CONFIG['to']))
    to_ent = ttk.Entry(frame, textvariable=to_var, width=40)
    to_ent.grid(row=4, column=1, padx=5, pady=2)

    # Log area
    log = scrolledtext.ScrolledText(frame, height=12, state='disabled')
    log.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

    def append_log(msg):
        log.config(state='normal')
        log.insert(tk.END, msg + "\n")
        log.config(state='disabled')
        log.see(tk.END)

    # Save settings button
    def save_settings():
        global smtp_handler
        for k, var in entries.items():
            CONFIG[k] = int(var.get()) if k=='port' else var.get()
        CONFIG['to'] = [addr.strip() for addr in to_var.get().split(',') if addr.strip()]
        logger.removeHandler(smtp_handler)
        smtp_handler = make_smtp_handler()
        logger.addHandler(smtp_handler)
        append_log("Settings saved and handler updated.")
        messagebox.showinfo("Mail Trace", "SMTP settings saved.")

    ttk.Button(frame, text="Save Settings", command=save_settings)\
        .grid(row=6, column=0, padx=5, pady=5)

    # Send Test Report button with updated behavior
    def send_test_report():
        append_log("Triggering test report...")
        try:
            raise RuntimeError("Test crash trigger.")
        except Exception:
            # Send the email and log it
            logger.exception("Manual test exception")
            append_log("Test exception logged and emailed.")

            # Rebuild and display the email body
            import traceback, datetime
            tb = traceback.format_exc()
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            body = (
                f"{ts}\n"
                f"MailTrace ERROR\n\n"
                f"Manual test exception\n"
                f"{tb}"
            )
            append_log("--- Email Content ---")
            for line in body.strip().splitlines():
                append_log(line)

            # Display the SMTP handshake trace
            append_log("--- SMTP TRACE ---")
            trace = getattr(smtp_handler, "debug_trace", "")
            for line in trace.strip().splitlines():
                append_log(line)

    ttk.Button(frame, text="Send Test Report", command=send_test_report)\
        .grid(row=6, column=1, padx=5, pady=5)

    # allow expansion
    frame.grid_rowconfigure(5, weight=1)
    frame.grid_columnconfigure(1, weight=1)
    return frame

if __name__ == "__main__":
    install_mail_trace()  # patch Tk
    # standalone test (won't send GUI)
    try:
        raise RuntimeError("This is a test exception")
    except Exception:
        import traceback
        tb = traceback.format_exc()
        print("Test crash report sent (check your app's Mail Trace tab).")
