#!/usr/bin/env python3
"""
batch_fill_payment_form.py

Batch‐fill and submit a payment form using a JSON list of names,
randomizing the order each run, with static payment details.
"""

import argparse
import json
import sys
import time
import random  # to shuffle the names list
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Static payment details (made-up test data)
CARD_NUMBER = "4242424242424242"      # Fake Visa test card number
EXPIRY = "12/25"                    # Fake expiry date
CVV = "123"                          # Fake CVV code
ADDRESS = "123 Testing Lane, Testville, TX 12345"  # Fake billing address


def fill_and_submit(driver, selectors, values, timeout=15):
    """
    Fill in form fields and click the submit button.

    :param driver: Selenium WebDriver instance
    :param selectors: dict mapping field names to CSS selectors
                      keys: "card_number", "expiry", "cvv", "name", "address", "submit"
    :param values: dict mapping field names to values to enter
    :param timeout: max seconds to wait for elements
    """
    # Wait helper
    wait = WebDriverWait(driver, timeout)

    # Fill each input field except the submit button
    for field, sel in selectors.items():
        if field == "submit":
            continue  # skip the button here
        # Wait until the element is present, then enter the value
        element = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, sel)))
        element.clear()
        element.send_keys(values[field])

    # Finally, click the submit button
    submit_btn = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, selectors["submit"])))
    submit_btn.click()


def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(
        description="Batch‐fill and submit payment form using a JSON list of names"
    )

    # URL of the payment form page
    parser.add_argument(
        "--url",
        required=True,
        help="Page URL containing the payment form"
    )
    # CSS selectors for each form field and the submit button
    parser.add_argument("--card-number-selector", required=True, help="CSS selector for card number input")
    parser.add_argument("--expiry-selector", required=True, help="CSS selector for expiry date input")
    parser.add_argument("--cvv-selector", required=True, help="CSS selector for CVV input")
    parser.add_argument("--name-selector", required=True, help="CSS selector for name input")
    parser.add_argument("--address-selector", required=True, help="CSS selector for address input")
    parser.add_argument("--submit-selector", required=True, help="CSS selector for submit button")
    # Path to the JSON file containing names array
    parser.add_argument(
        "--names-file",
        required=True,
        help="Path to JSON file with array of names (e.g. ['Alice','Bob',...])"
    )

    args = parser.parse_args()

    # Load names list from JSON file
    try:
        with open(args.names_file, 'r', encoding='utf-8') as f:
            names = json.load(f)
        if not isinstance(names, list):
            raise ValueError("Expected a JSON array of strings")
    except Exception as e:
        print(f"[ERROR] Failed to load names from {args.names_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # Shuffle the list to randomize submission order
    random.shuffle(names)

    # Bundle all selectors into a dict for reuse
    selectors = {
        "card_number": args.card_number_selector,
        "expiry":      args.expiry_selector,
        "cvv":         args.cvv_selector,
        "name":        args.name_selector,
        "address":     args.address_selector,
        "submit":      args.submit_selector,
    }

    # Initialize Selenium WebDriver (Chrome)
    options = webdriver.ChromeOptions()
    # Uncomment to run in headless mode (browser UI hidden)
    # options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)

    try:
        # Iterate over each name and submit the form
        for idx, name in enumerate(names, start=1):
            print(f"→ [{idx}/{len(names)}] Submitting form for: {name}")
            # Navigate to the URL
            driver.get(args.url)

            # Prepare values dict for this iteration
            values = {
                "card_number": CARD_NUMBER,
                "expiry":      EXPIRY,
                "cvv":         CVV,
                "name":        name,
                "address":     ADDRESS,
            }

            # Attempt to fill and submit; catch per-name errors
            try:
                fill_and_submit(driver, selectors, values)
                print("   ✔ Submitted.")
            except Exception as e:
                print(f"   [ERROR] Submission failed for '{name}': {e}", file=sys.stderr)

            # Throttle submissions: wait 1 second before next
            time.sleep(1)

    finally:
        # Always quit the browser session
        driver.quit()

# now we await scam emails 
if __name__ == "__main__":
    main()
