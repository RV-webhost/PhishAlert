import re 
import json
import os
from datetime import datetime
import tkinter as tk  # For creating the GUI (Graphical User Interface)
from tkinter import ttk, scrolledtext, messagebox  # Additional GUI components

print("All import setup successful!")

class SimplePhisingDetector:
    def __init__(self):
        # List of suspicious websites/domains
        self.bad_domains = [
            'bit.ly', 'tinyurl.com',
            'secure-bank-update', 'urgent-verification',
            'free-money', 'prize-winner'
        ]
        
        # List of legitimate websites
        self.good_domains = [
            'google.com', 'sbi.co.in',
            'icicibank.com', 'amazon.in', 'paytm.com'
        ]
        
        # Scam message patterns
        self.scam_words = {
            'urgent': ['urgent', 'immediate', 'expires today', 'act now'],
            'money': ['you have won', 'prize money', 'free money', 'claim now'],
            'banking': ['account suspended', 'verify account', 'update kyc'],
            'phishing': ['click here', 'verify identity', 'confirm details']
        }

        print("Detector Brain Created")

    def check_url(self, url):
        print(f"Checking the url: {url}")

        if not url:
            return "Please Enter the URL!"

        url = url.lower()
        danger_score = 0
        warnings = []

        # Is it a bad domain in url
        for bad_domain in self.bad_domains:
            if bad_domain in url:
                danger_score += 3
                warnings.append(f"⚠️ Contains suspicious domain: {bad_domain}")

        # Is it a good_domain
        is_good_domain = False
        for good_domain in self.good_domains:
            if good_domain in url:
                is_good_domain = True
                break

        # Does it use HTTPS (secure connection)?
        if not url.startswith('https://'):
            danger_score += 2
            warnings.append("⚠️ Not using secure HTTPS connection")

        # check whether url contains any IP address instead of domain
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            danger_score += 4
            warnings.append("🚨 Using IP address instead of domain name")

        # Now let decide how dangerous this url is
        if is_good_domain and danger_score <= 1:
            result = "✅ SAFE: This appears to be a legitimate website"
        elif danger_score >= 5:
            result = "🚨 DANGER: This URL is highly suspicious!"
        elif danger_score >= 2:
            result = "⚠️ WARNING: This URL has some red flags"
        else:
            result = "❓ UNKNOWN: Be cautious with this URL"

        return {
            'message': result,
            'score': danger_score,
            'warnings': warnings
        }

    def check_messages(self, message):
        print("Analysing the message.....")

        if not message:
            return 'Please Enter The Message!'
        
        message = message.lower()
        danger_score = 0
        found_patterns = []

        # Check each category of scam words
        for category, words in self.scam_words.items():
            for word in words:
                if word in message:
                    danger_score += 2
                    found_patterns.append(f"{category.title()}: '{word}'")

        # Check for phone numbers (scammers often include phone numbers)
        if re.search(r'\d{10}', message):
            danger_score += 1
            found_patterns.append("Phone number detected")

        # Check for generic greetings (sign of mass scam messages)
        if 'dear coustmer' in message or 'dear sir' in message:
            danger_score += 1
            found_patterns.append("Generic greeting (not personalized)")
            
        # Decide danger level
        if danger_score >= 6:
            result = "🚨 DANGER: This message shows multiple scam signs!"
        elif danger_score >= 3:
            result = "⚠️ WARNING: This message has suspicious elements"
        elif danger_score >= 1:
            result = "❓ CAUTION: Some concerning patterns found"
        else:
            result = "✅ SAFE: Message appears relatively safe"

        return {
            'message': result,
            'score': danger_score,
            'patterns': found_patterns
        }


# Creating GUI
class PhisingDetectorApp:
    def __init__(self):
        print("Creating user Interface")

        # Create the main window
        self.root = tk.Tk()
        self.root.title("🛡️ Phishing Detector - Learning Version")
        self.root.geometry("800x600")

        # Create our detector brain
        self.detector = SimplePhisingDetector()  # not work becz didnt get input

         # Build the interface
        self.create_interface()

        print("Step 3: Interface created! ✅")

    def create_interface(self):
        """
        This function creates all the buttons, text boxes, and other interface elements
        """

        # Main Title
        title_label = tk.Label(self.root, text="🛡️ Phishing Detector", font=("Arial", 20, "bold"))
        title_label.pack(pady=10)

        # Create tabs for different sections
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: URL Checker
        self.create_url_tab()
        
        # Tab 2: Message Checker
        self.create_message_tab()
        
        # Tab 3: Education
        self.create_education_tab()

    def create_url_tab(self):
        """
        Create the URL checking tab
        """

        # create a frame
        url_frame = ttk.Frame(self.notebook)
        self.notebook.add(url_frame, text="🔗 URL Checker")

        # Instruction
        Instructions = tk.Label(url_frame,
                                text="Enter a URL to check if it's safe or suspicious:",
                                font=("Arial", 12))
        Instructions.pack(pady=10)

        # URL input box
        self.url_entry = tk.Entry(url_frame, width=80, font=("Arial", 11))
        self.url_entry.pack(pady=5) 

        # Button to check URL
        check_button = tk.Button(url_frame, text="🔍 Check URL",
                                  command=self.check_url_clicked,
                                 bg="#4CAF50", fg="white", font=("Arial", 11))
        check_button.pack(pady=10)

        # Results display area
        self.url_result = scrolledtext.ScrolledText(url_frame, height=15, width=90)
        self.url_result.pack(fill="both", expand=True, pady=10, padx=10)

    def create_message_tab(self):
        """
        Create the message checking tab
        """

        message_frame = ttk.Frame(self.notebook)
        self.notebook.add(message_frame, text="📱 Message Checker")

        # Instruction
        instruction = tk.Label(message_frame,
                                text="Paste a suspicious message to analyze:",
                                font=("Arial", 12))
        instruction.pack(pady=10)

        # Message input area
        self.message_entry = scrolledtext.ScrolledText(message_frame, height=8, width=90)
        self.message_entry.pack(pady=5, padx=10, fill='x')

        # Button to analyze message
        analyze_button = tk.Button(message_frame, text="🔍 Analyze Message",
                                   command=self.check_message_clicked, bg="#2196F3", fg="white", font=("Arial", 11))
        analyze_button.pack(pady=10)

        # Results display area
        self.message_display = scrolledtext.ScrolledText(message_frame, height=15, width=90)
        self.message_display.pack(pady=10, padx=10, fill='both', expand=True)

    def create_education_tab(self):
        """
        Create the education tab with safety tips
        """
        education_frame = ttk.Frame(self.notebook)
        self.notebook.add(education_frame, text="📚 Safety Tips")
        
        # Education content
        education_text = scrolledtext.ScrolledText(education_frame, wrap=tk.WORD, width=100, height=30)
        education_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add educational content
        tips = """
                🛡️ CYBERSECURITY SAFETY GUIDE FOR BEGINNERS

                === WHAT ARE PHISHING ATTACKS? ===
                Phishing is when criminals try to trick you into giving them your personal information
                (like passwords, bank details, or credit card numbers) by pretending to be someone trustworthy.

                === COMMON TRICKS SCAMMERS USE ===
                • Urgent messages: "Your account will be closed in 24 hours!"
                • Fake prizes: "You've won ₹1 lakh! Click here to claim!"
                • Fake security alerts: "Your account has been compromised!"
                • Tech support scams: "Your computer is infected!"

                === DO's - ALWAYS DO THESE ===
                ✅ Check the sender's email address carefully
                ✅ Look for spelling and grammar mistakes
                ✅ Verify urgent requests through official channels
                ✅ Use strong, unique passwords
                ✅ Keep your software updated
                ✅ Trust your instincts - if something feels wrong, it probably is

                === DON'Ts - NEVER DO THESE ===
                ❌ Don't click suspicious links
                ❌ Don't share passwords or PINs with anyone
                ❌ Don't download attachments from unknown senders
                ❌ Don't use public WiFi for banking
                ❌ Don't trust "urgent" money requests
                ❌ Don't give remote access to strangers

                === HOW TO SPOT FAKE URLS ===
                • Check for misspellings: "gooogle.com" instead of "google.com"
                • Look for suspicious domains: "secure-bank-update.com"
                • Make sure it starts with "https://" (the 's' means secure)
                • Be wary of shortened URLs (bit.ly, tinyurl.com)

                === WHAT TO DO IF YOU THINK YOU'VE BEEN SCAMMED ===
                1. Don't panic!
                2. Change your passwords immediately
                3. Contact your bank if money was involved
                4. Report it to cybercrime.gov.in
                5. Tell your friends and family to be aware

                === REMEMBER ===
                • Banks will NEVER ask for your password in an email
                • Real companies use your name, not "Dear Customer"
                • If it's too good to be true, it probably is
                • When in doubt, ask a tech-savvy friend or family member

                Stay safe online! 🛡️
                """
        
        education_text.insert(tk.END, tips)
        education_text.config(state="disabled") # Make it read-only

    def check_url_clicked(self):
        """
        This function runs when the user clicks the "Check URL" button
        """

        # Get url from input box
        url = self.url_entry.get()

        # Clear previous result
        self.url_result.delete(1.0, tk.END)

         # Show "checking..." message
        self.url_result.insert(tk.END, "🔍 Checking URL...\n\n")
        self.root.update()  # Update the display

        # Check the URL using our detector
        result = self.detector.check_url(url)

        # Clear the "checking..." message
        self.url_result.delete(1.0, tk.END)

        # Display results
        self.url_result.insert(tk.END, f"RESULT: {result['message']}\n")
        self.url_result.insert(tk.END, f"Danger Score: {result['score']}/10\n\n")
        
        if result['warnings']:
            self.url_result.insert(tk.END, "⚠️ WARNINGS FOUND:\n")
            for warning in result['warnings']:
                self.url_result.insert(tk.END, f"• {warning}\n")
        
        # Add explanation for beginners
        self.url_result.insert(tk.END, f"\n💡 EXPLANATION:\n")
        self.url_result.insert(tk.END, f"We checked this URL against our database of known threats.\n")
        self.url_result.insert(tk.END, f"Danger scores above 3 are concerning, above 5 are dangerous.\n")

    def check_message_clicked(self):
        """
        This function runs when the user clicks the "Analyze Message" button
        """

        # Get the message from the input area
        message = self.message_entry.get(1.0, tk.END)

        # Clear previous results
        self.message_display.delete(1.0, tk.END)

        # Show "analyzing..." message
        self.message_display.insert(tk.END, "🔍 Analyzing message...\n\n")
        self.root.update()

        # Analyze the message
        result = self.detector.check_messages(message)

        # Clear the analyze message
        self.message_display.delete(1.0, tk.END)

        # Display result
        self.message_display.insert(tk.END, f"RESULT: {result['message']}\n")
        self.message_display.insert(tk.END, f"Danger Score: {result['score']}/10\n\n")

        if result['patterns']:
            self.message_display.insert(tk.END, "🚨 SUSPICIOUS PATTERNS FOUND:\n")
            for pattern in result['patterns']:
                self.message_display.insert(tk.END, f"• {pattern}\n")
        
        # Add explanation
        self.message_display.insert(tk.END, f"\n💡 EXPLANATION:\n")
        self.message_display.insert(tk.END, f"We looked for common scam patterns in this message.\n")
        self.message_display.insert(tk.END, f"Higher scores indicate more suspicious content.\n")



    def run(self):
        print("Step 4: Starting application... 🚀")
        self.root.mainloop()

# APP RUNS Here
def main():
    print("🛡️ PHISHING DETECTOR - LEARNING VERSION")
    print("="*50)

    try:
        app = PhisingDetectorApp()
        app.run()

    except Exception as e:
        print(f"❌ Error: {e}")

# Program starts here
if __name__ == "__main__":
    main()
 # type: ignore