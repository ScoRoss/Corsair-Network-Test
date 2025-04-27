# Corsair Network Test Tool
# Mail Trace Module
# This module provides functionality to send crash reports via email using SMTP,
# captures unhandled exceptions in Tkinter callbacks and sends the traceback to a specified email,
# and provides a GUI interface to test email functionality and view the SMTP trace only.
# mail trace alpha 0.1

import logging
from logging.handlers import SMTPHandler
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import smtplib, io

# --------------------------------------------------
# Default SMTP configuration; will be overridden via GUI
CONFIG = {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "coonta75@gmail.com",
    "pass": "",
    "to":   ["coonta75@gmail.com"],
}
# --------------------------------------------------

class TracingSMTPHandler(SMTPHandler):
    def emit(self, record):
        try:
            debug_buf = io.StringIO()
            port = self.mailport or smtplib.SMTP_PORT
            smtp = smtplib.SMTP(self.mailhost, port, timeout=self.timeout)
            smtp.set_debuglevel(1)

            def capture_debug(*args):
                debug_buf.write(" ".join(str(a) for a in args) + "\n")
            smtp._print_debug = capture_debug

            if self.username:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self.username, self.password)

            msg = self.format(record)
            full_msg = msg + "\n\n--- SMTP TRACE ---\n" + debug_buf.getvalue()

            smtp.sendmail(self.fromaddr, self.toaddrs, full_msg)
            smtp.quit()
            self.debug_trace = debug_buf.getvalue()
        except Exception:
            self.handleError(record)

# Logger setup
logger = logging.getLogger("MailTrace")
logger.setLevel(logging.ERROR)
logger.propagate = False

# Factory for tracing handler
def make_smtp_handler():
    handler = TracingSMTPHandler(
        mailhost=(CONFIG["host"], CONFIG["port"]),
        fromaddr=CONFIG["user"],
        toaddrs=CONFIG["to"],
        subject="Crash Report: Network Test Tool",
        credentials=(CONFIG["user"], CONFIG["pass"]),
        secure=(),
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

# Hook uncaught Tkinter exceptions
def report_callback_exception(self, exc, val, tb):
    logger.exception("Unhandled exception in Tkinter callback", exc_info=(exc, val, tb))

# Install before tk.Tk()
def install_mail_trace():
    tk.Tk.report_callback_exception = report_callback_exception
    return lambda f: f

# Create the Mail Trace tab
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

    # Save Settings
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

    # Send Test Report
    def send_test_report():
        append_log("Triggering test report...")
        try:
            raise RuntimeError("Test crash trigger.")
        except Exception:
            # send and log exception
            logger.exception("Manual test exception")
            append_log("Test exception logged and emailed.")

            # display only the SMTP TRACE
            append_log("--- SMTP TRACE ---")
            trace = getattr(smtp_handler, "debug_trace", "")
            for line in trace.strip().splitlines():
                append_log(line)

    ttk.Button(frame, text="Send Test Report", command=send_test_report)\
        .grid(row=6, column=1, padx=5, pady=5)

    frame.grid_rowconfigure(5, weight=1)
    frame.grid_columnconfigure(1, weight=1)
    return frame

if __name__ == "__main__":
    install_mail_trace()
    try:
        raise RuntimeError("This is a test exception")
    except Exception:
        import traceback
        print("Test crash report sent (check your app's Mail Trace tab).")
