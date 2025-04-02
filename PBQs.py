import tkinter as tk
from tkinter import messagebox
import random

class QuizApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Performance-Based Questions Quiz")
        self.geometry("960x960")
        self.pages = []
        self.current_page_index = 0
        self.responses = {}  # dictionary to store responses

        # Dummy answer keys for demonstration purposes.
        # The structure here should match how each page saves its responses.
        self.answer_keys = {
            "A1": {"A1_Q1": "Injection", "A1_Q2": "On-path", "A1_Q3": "DDoS", "A1_Q4": "Keylogger", "A1_Q5": "Vishing"},
            "A2": {
                "Outside Building": ["Access Badge", "Lighting"],
                "Reception": ["Fencing", "Security Guard"],
                "Data Center Door": ["Access control vestibule", "Authentication token"],
                "Server Administration": ["Biometrics"]
            },
            "A3": {"A3_Q1": "Operational", "A3_Q2": "Managerial", "A3_Q3": "Physical", "A3_Q4": "Technical", "A3_Q5": "Technical"},
            "A4": {"A4_Q1": "Something you have", "A4_Q2": "Something you know", "A4_Q3": "Something you are", "A4_Q4": "Somewhere you are"},
            "A5": {
                "A5_Rule1": {"Source IP": "10.1.1.3", "Destination IP": "10.1.1.7", "Protocol": "TCP", "Port": "80", "Allow/Block": "Block"},
                "A5_Rule2": {"Source IP": "10.2.1.33", "Destination IP": "10.2.1.47", "Protocol": "UDP", "Port": "443", "Allow/Block": "Allow"},
                "A5_Rule3": {"Source IP": "10.2.1.20", "Destination IP": "10.1.1.3", "Protocol": "TCP", "Port": "22", "Allow/Block": "Block"}
            },
            "B1": {"B1_Q1": "CRL", "B1_Q2": "CSR", "B1_Q3": "CA", "B1_Q4": "OCSP"},
            "B2": {
                "Desktop Feature 1": "Anti-malware",
                "Desktop Feature 2": "MDM integration",
                "Tablet Feature 1": "Full device encryption",
                "Tablet Feature 2": "Biometric authentication",
                "Tablet Feature 3": "Host-based firewall"
            },
            "B3": {"order": ["Preparation", "Detection", "Analysis", "Containment", "Eradication", "Recovery", "Lessons learned"]},
            "B4": {"B4_Q1": "Hashing", "B4_Q2": "Digital signature", "B4_Q3": "SPF", "B4_Q4": "Key escrow", "B4_Q5": "Journaling", "B4_Q6": "Obfuscation"},
            "B5": {"B5_Q1": "Data in-transit", "B5_Q2": "Data in-transit", "B5_Q3": "Data at-rest", "B5_Q4": "Data in-use",
                    "B5_Q5": "Data in-use", "B5_Q6": "Data at-rest", "B5_Q7": "Data in-use", "B5_Q8": "Data at-rest",
                    "B5_Q9": "Data in-transit", "B5_Q10": "Data at-rest"},
            "C1": {"C1_Q1": "ALLOWED", "C1_Q2": "BLOCKED", "C1_Q3": "ALLOWED", "C1_Q4": "ALLOWED", "C1_Q5": "BLOCKED", "C1_Q6": "ALLOWED"},
            "C2": {"C2_Q1": "WAF", "C2_Q2": "Proxy Server", "C2_Q3": "Load Balancer", "C2_Q4": "Sensor", "C2_Q5": "MDM Router"},
            "C3": {"C3_Q1": "DDoS", "C3_Q2": "Replay", "C3_Q3": "Rootkit", "C3_Q4": "Brute force", "C3_Q5": "Phishing", "C3_Q6": "Injection"},
            "C4": {"C4_Q1": "Key stretching", "C4_Q2": "Steganography", "C4_Q3": "Collision", "C4_Q4": "Masking", "C4_Q5": "Asymmetric", "C4_Q6": "Salting"},
            "C5": {"C5_Q1": "VPN", "C5_Q2": "Sandboxing", "C5_Q3": "NGFW", "C5_Q4": "SD-WAN", "C5_Q5": "802.1X"}
        }

        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        self.container = container
        self.create_pages()
        self.show_page(0)

    def create_pages(self):
        # Create instances of each page and add them to self.pages list.
        self.pages.append(A1Page(self.container, self))
        self.pages.append(A2Page(self.container, self))
        self.pages.append(A3Page(self.container, self))
        self.pages.append(A4Page(self.container, self))
        self.pages.append(A5Page(self.container, self))
        self.pages.append(B1Page(self.container, self))
        self.pages.append(B2Page(self.container, self))
        self.pages.append(B3Page(self.container, self))
        self.pages.append(B4Page(self.container, self))
        self.pages.append(B5Page(self.container, self))
        self.pages.append(C1Page(self.container, self))
        self.pages.append(C2Page(self.container, self))
        self.pages.append(C3Page(self.container, self))
        self.pages.append(C4Page(self.container, self))
        self.pages.append(C5Page(self.container, self))

    def show_page(self, index):
        # Hide all pages and show page at index.
        for page in self.pages:
            page.pack_forget()
        self.pages[index].pack(fill="both", expand=True)
        self.current_page_index = index

    def next_page(self):
        # Evaluate section if the current page is the last page in a section.
        # Section A: pages 0-4, Section B: pages 5-9, Section C: pages 10-14.
        section_end_pages = {4: "A", 9: "B", 14: "C"}
        if self.current_page_index in section_end_pages:
            self.evaluate_section(section_end_pages[self.current_page_index])
        if self.current_page_index < len(self.pages) - 1:
            self.show_page(self.current_page_index + 1)
        else:
            self.finish_quiz()

    def prev_page(self):
        if self.current_page_index > 0:
            self.show_page(self.current_page_index - 1)

    def finish_quiz(self):
        # Evaluate section C if not already done.
        if self.current_page_index == 14:
            self.evaluate_section("C")
        result = "Quiz Completed! Your responses:\n\n"
        for key, value in self.responses.items():
            result += f"{key}: {value}\n"
        messagebox.showinfo("Results", result)
        self.destroy()

    def evaluate_section(self, section):
        # Determine which page IDs belong to the section.
        if section == "A":
            page_ids = ["A1", "A2", "A3", "A4", "A5"]
        elif section == "B":
            page_ids = ["B1", "B2", "B3", "B4", "B5"]
        elif section == "C":
            page_ids = ["C1", "C2", "C3", "C4", "C5"]

        total_questions = 0
        correct = 0
        feedback_lines = []
        for pid in page_ids:
            if pid not in self.responses:
                continue
            page_resp = self.responses[pid]
            correct_answers = self.answer_keys.get(pid, {})
            # For pages that return a dictionary of responses (e.g., A1, A3, A4, C1, etc.)
            if isinstance(page_resp, dict) and isinstance(correct_answers, dict):
                for q, corr_ans in correct_answers.items():
                    total_questions += 1
                    user_ans = page_resp.get(q, "")
                    # If the answer is a nested dictionary (as in A5), compare each field.
                    if isinstance(corr_ans, dict):
                        for sub_q, sub_corr in corr_ans.items():
                            total_questions += 1
                            user_sub_ans = user_ans.get(sub_q, "") if isinstance(user_ans, dict) else ""
                            if user_sub_ans == sub_corr:
                                correct += 1
                            else:
                                feedback_lines.append(f"{pid} {q} - {sub_q}: Your answer: {user_sub_ans} | Correct: {sub_corr}")
                    else:
                        if user_ans == corr_ans:
                            correct += 1
                        else:
                            feedback_lines.append(f"{pid} {q}: Your answer: {user_ans} | Correct: {corr_ans}")
            # Special case for page B3 (ordering question)
            elif isinstance(page_resp, list) and pid == "B3":
                total_questions += 1
                correct_order = correct_answers.get("order", [])
                if list(page_resp) == correct_order:
                    correct += 1
                else:
                    feedback_lines.append(f"{pid}: Your order: {list(page_resp)} | Correct order: {correct_order}")
            # Special case for page A2 (each location returns a list)
            elif isinstance(page_resp, dict) and pid == "A2":
                for loc, user_ans_list in page_resp.items():
                    total_questions += 1
                    corr_ans_list = correct_answers.get(loc, [])
                    if user_ans_list == corr_ans_list:
                        correct += 1
                    else:
                        feedback_lines.append(f"{pid} {loc}: Your answers: {user_ans_list} | Correct: {corr_ans_list}")
        score_percent = (correct / total_questions) * 100 if total_questions else 0
        msg = f"Section {section} Score: {correct} out of {total_questions} correct ({score_percent:.1f}%).\n"
        if feedback_lines:
            msg += "\nIncorrect Answers:\n" + "\n".join(feedback_lines)
        else:
            msg += "\nAll answers are correct!"
        messagebox.showinfo(f"Section {section} Feedback", msg)


# -----------------------------
# NavigationFrame using place()
# -----------------------------
class NavigationFrame(tk.Frame):
    def __init__(self, parent, controller):
        # Set fixed size for the navigation frame
        tk.Frame.__init__(self, parent, width=200, height=50)
        self.controller = controller
        self.config(bg="lightgray")
        # Place at the top right corner of its parent.
        self.place(relx=1.0, rely=0.0, anchor="ne")
        
        # Previous button at the top left of the navigation frame
        prev_btn = tk.Button(self, text="Previous", command=self.go_prev, font=("Arial", 12))
        prev_btn.place(relx=0.0, rely=0.5, anchor="w", x=10)
        # Next button at the top right of the navigation frame
        next_btn = tk.Button(self, text="Next", command=self.go_next, font=("Arial", 12))
        next_btn.place(relx=1.0, rely=0.5, anchor="e", x=-10)

    def go_next(self):
        self.controller.pages[self.controller.current_page_index].save_responses()
        self.controller.next_page()

    def go_prev(self):
        self.controller.pages[self.controller.current_page_index].save_responses()
        self.controller.prev_page()


# -----------------------------
# Page A1: Matching Attack Types (5 sub-questions)
# -----------------------------
class A1Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "A1"
        title = tk.Label(self, text="A1. Match the description with the most accurate attack type.\n(Not all attack types will be used.)", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        instructions = tk.Label(self, text="Select an attack type from the dropdown for each description:", font=("Arial", 12))
        instructions.pack(pady=5)

        self.attack_types = ["On-path", "RFID cloning", "Keylogger", "Vishing", "Rootkit", "DDoS", "Injection", "Supply chain"]
        self.subquestions = [
            "Attacker accesses a database directly from a web browser",
            "Attacker intercepts all communication between a client and a web server",
            "Multiple attackers overwhelm a web server",
            "Attacker obtains a list of all login credentials used over the last 24 hours",
            "Attacker obtains bank account number and birth date by calling the victim"
        ]
        self.vars = []
        for idx, desc in enumerate(self.subquestions):
            frame = tk.Frame(self)
            frame.pack(pady=5, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {desc}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select an Attack Type")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.attack_types)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        # Create navigation frame without pack (it will use place inside NavigationFrame)
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"A1_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page A2: Security Controls for Locations
# -----------------------------
class A2Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "A2"
        
        title = tk.Label(self, text="A2. Select the BEST security control for each location.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        
        instruction = tk.Label(self, text="All of the available controls will be used once.", font=("Arial", 12, "bold"))
        instruction.pack(pady=5)
        
        options = ["Access Badge", "Fencing", "Access control vestibule", "Security Guard", "Authentication token", "Biometrics", "Lighting"]
        self.subquestions = [
            {"number": 1, "location": "Outside Building", "description": "Parking and Visitor drop-off", "allowed": 2, "options": options},
            {"number": 2, "location": "Reception", "description": "Building lobby", "allowed": 2, "options": options},
            {"number": 3, "location": "Data Center Door", "description": "Entrance from inside building", "allowed": 2, "options": options},
            {"number": 4, "location": "Server Administration", "description": "Authentication to server console in the data center", "allowed": 1, "options": options}
        ]

        self.vars = {}
        for sq in self.subquestions:
            frame = tk.Frame(self)
            frame.pack(pady=5, anchor="center")
            lbl_text = f"{sq['number']}. {sq['location']} ({sq['description']}):"
            lbl = tk.Label(frame, text=lbl_text, font=("Arial", 12), justify="center")
            lbl.grid(row=0, column=0, columnspan=sq["allowed"], pady=2)
            self.vars[sq["location"]] = []
            for i in range(sq["allowed"]):
                var = tk.StringVar()
                var.set("Select a Security Control")
                self.vars[sq["location"]].append(var)
                dropdown = tk.OptionMenu(frame, var, *sq["options"])
                dropdown.config(font=("Arial", 12))
                dropdown.grid(row=1, column=i, padx=5, pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for location, var_list in self.vars.items():
            responses = [var.get() for var in var_list]
            answers[location] = responses
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page A3: Security Category Selection
# -----------------------------
class A3Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "A3"
        title = tk.Label(self, text="A3. Select the most appropriate security category.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each statement, choose a category. Options: Operational, Managerial, Physical, Technical", font=("Arial", 12))
        info.pack(pady=5)
        extra_info = tk.Label(self, text="Some categories may be used more than once.", font=("Arial", 12, "bold"))
        extra_info.pack(pady=5)

        self.statements = [
            "A guard checks the identification of all visitors",
            "All returns must be approved by a Vice President",
            "A generator is used during a power outage",
            "Building doors can be unlocked with an access card",
            "System logs are transferred automatically to a SIEM"
        ]
        self.options = ["Operational", "Managerial", "Physical", "Technical"]
        self.vars = []
        for idx, stmt in enumerate(self.statements):
            frame = tk.Frame(self)
            frame.pack(pady=5, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {stmt}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select a Category")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"A3_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page A4: Authentication Factor Matching
# -----------------------------
class A4Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "A4"
        title = tk.Label(self, text="A4. Match the appropriate authentication factor to each description.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="Options: Somewhere you are, Something you have, Something you are, Something you know", font=("Arial", 12))
        info.pack(pady=5)
        extra_info = tk.Label(self, text="each authentication factor will be used exactly once.", font=("Arial", 12, "bold"))
        extra_info.pack(pady=5)

        self.statements = [
            "During the login process, your phone receives a text message with a one-time passcode",
            "You enter your PIN to make a deposit into an ATM",
            "You can use your fingerprint to unlock the door to the data center",
            "Your login will not work unless you are connected to the VPN"
        ]
        self.options = ["Somewhere you are", "Something you have", "Something you are", "Something you know"]
        self.vars = []
        for idx, stmt in enumerate(self.statements):
            frame = tk.Frame(self)
            frame.pack(pady=5, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {stmt}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select an Authentication Factor")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"A4_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page A5: Firewall Rule Configuration (Image above Response Table)
# -----------------------------
class A5Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "A5"
        
        # Title and info labels
        title = tk.Label(self, text="A5. Configure the following stateful firewall rules.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="Enter the rule details using the dropdown menus below.", font=("Arial", 12))
        info.pack(pady=5)
        
        # Top frame: contains prompt on left and navigation buttons on right
        top_frame = tk.Frame(self)
        top_frame.pack(fill="x", padx=10, pady=5)
        
        prompt_text = ("• Block HTTP sessions between the Web Server and the Database Server\n"
                       "• Allow the Storage Server to transfer files to the Video Server over HTTPS\n"
                       "• Allow the Management Server to use a secure terminal on the File Server")
        prompt_lbl = tk.Label(top_frame, text=prompt_text, font=("Arial", 12), justify="left")
        prompt_lbl.pack(side="left", fill="x", expand=True)
        
        # Local navigation frame in top_frame
        nav_frame = tk.Frame(top_frame)
        nav_frame.pack(side="right")
        prev_btn = tk.Button(nav_frame, text="Previous", command=self.go_prev, font=("Arial", 12))
        prev_btn.pack(side="left", padx=5)
        next_btn = tk.Button(nav_frame, text="Next", command=self.go_next, font=("Arial", 12))
        next_btn.pack(side="left", padx=5)
        
        # IMAGE FRAME: Now placed above the response area
        image_frame = tk.Frame(self)
        image_frame.pack(pady=10)
        try:
            self.firewall_image = tk.PhotoImage(file="A4Firewall.png")
            # Adjust the subsample factor as needed for scaling
            self.firewall_image = self.firewall_image.subsample(2, 2)
            img_label = tk.Label(image_frame, image=self.firewall_image)
            img_label.pack(expand=True)
        except Exception as e:
            img_label = tk.Label(image_frame, text="Image A4Firewall.png not found", font=("Arial", 12))
            img_label.pack(expand=True)
        
        # TABLE FRAME: Holds the response table and now appears below the image
        table_frame = tk.Frame(self)
        table_frame.pack(pady=10, padx=10)
        
        headers = ["Rule#", "Source IP", "Destination IP", "Protocol (TCP/UDP)", "Port #", "Allow/Block"]
        for col, header in enumerate(headers):
            lbl = tk.Label(table_frame, text=header, font=("Arial", 12, "bold"),
                           borderwidth=1, relief="solid", padx=5, pady=5)
            lbl.grid(row=0, column=col, sticky="nsew")
        
        ip_options = ["10.1.1.3", "10.1.1.7", "10.2.1.33", "10.2.1.47", "10.2.1.20"]
        protocol_options = ["TCP", "UDP"]
        port_options = ["80", "443", "22"]
        allow_options = ["Allow", "Block"]
        
        self.table_vars = []  # List to hold dictionaries of row variables
        # Create exactly 3 data rows (one per rule)
        for i in range(3):
            row_vars = {}
            # Column 0: Rule number label
            rule_lbl = tk.Label(table_frame, text=str(i+1), font=("Arial", 12),
                                borderwidth=1, relief="solid", padx=5, pady=5)
            rule_lbl.grid(row=i+1, column=0, sticky="nsew")
            # Column 1: Source IP
            var_source = tk.StringVar()
            var_source.set("Select")
            row_vars["Source IP"] = var_source
            opt_source = tk.OptionMenu(table_frame, var_source, *ip_options)
            opt_source.config(font=("Arial", 12))
            opt_source.grid(row=i+1, column=1, sticky="nsew", padx=2, pady=2)
            # Column 2: Destination IP
            var_dest = tk.StringVar()
            var_dest.set("Select")
            row_vars["Destination IP"] = var_dest
            opt_dest = tk.OptionMenu(table_frame, var_dest, *ip_options)
            opt_dest.config(font=("Arial", 12))
            opt_dest.grid(row=i+1, column=2, sticky="nsew", padx=2, pady=2)
            # Column 3: Protocol (TCP/UDP)
            var_protocol = tk.StringVar()
            var_protocol.set("Select")
            row_vars["Protocol"] = var_protocol
            opt_protocol = tk.OptionMenu(table_frame, var_protocol, *protocol_options)
            opt_protocol.config(font=("Arial", 12))
            opt_protocol.grid(row=i+1, column=3, sticky="nsew", padx=2, pady=2)
            # Column 4: Port #
            var_port = tk.StringVar()
            var_port.set("Select")
            row_vars["Port"] = var_port
            opt_port = tk.OptionMenu(table_frame, var_port, *port_options)
            opt_port.config(font=("Arial", 12))
            opt_port.grid(row=i+1, column=4, sticky="nsew", padx=2, pady=2)
            # Column 5: Allow/Block
            var_allow = tk.StringVar()
            var_allow.set("Select")
            row_vars["Allow/Block"] = var_allow
            opt_allow = tk.OptionMenu(table_frame, var_allow, *allow_options)
            opt_allow.config(font=("Arial", 12))
            opt_allow.grid(row=i+1, column=5, sticky="nsew", padx=2, pady=2)
            
            self.table_vars.append(row_vars)
        
    def go_next(self):
        self.save_responses()
        self.controller.next_page()
    
    def go_prev(self):
        self.save_responses()
        self.controller.prev_page()
    
    def save_responses(self):
        answers = {}
        for i, row in enumerate(self.table_vars):
            answers[f"A5_Rule{i+1}"] = {
                "Source IP": row["Source IP"].get(),
                "Destination IP": row["Destination IP"].get(),
                "Protocol": row["Protocol"].get(),
                "Port": row["Port"].get(),
                "Allow/Block": row["Allow/Block"].get()
            }
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page B1: Certificate Characteristic Matching
# -----------------------------
class B1Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B1"
        title = tk.Label(self, text="B1. Match the certificate characteristic to the description.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each description, select the appropriate certificate characteristic.", font=("Arial", 12))
        info.pack(pady=5)

        self.descriptions = [
            "A list of invalidated certificates",
            "Send the public key to be signed",
            "Deploy and manage certificates",
            "The browser checks for a revoked certificate"
        ]
        self.options = ["CRL", "CA", "OCSP", "CSR"]
        self.vars = []
        for idx, desc in enumerate(self.descriptions):
            frame = tk.Frame(self)
            frame.pack(pady=5, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {desc}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select a Certificate Characteristic")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"B1_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page B2: Security Features for Mobile App Deployment
# -----------------------------
class B2Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B2"
        title = tk.Label(self, text="B2. Device security features.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        
        # Context text for the question:
        context_text = (
            "An organization is deploying a mobile app to its sales team in the field.\n"
            "The application will be accessed from tablets for remote team members and a browser-based front-end on desktops for corporate office users.\n"
            "The application contains sensitive customer information, and two forms of authentication are required to launch the application."
        )
        context_lbl = tk.Label(self, text=context_text, font=("Arial", 12), wraplength=900, justify="left")
        context_lbl.pack(pady=10, padx=10)
        
        # Bold directions
        directions_text = "Select the best security features for each platform. A security feature will only be used once. Not all security features will be used."
        directions_lbl = tk.Label(self, text=directions_text, font=("Arial", 12, "bold"), wraplength=900, justify="left")
        directions_lbl.pack(pady=5, padx=10)
        
        # Define the available security feature options:
        self.options = [
            "Anti-malware", "MDM integration", "Full device encryption", "Biometric authentication", 
            "Host-based firewall", "Infrared sensors", "OSINT"
        ]
        
        # Desktop section: allows for two security features.
        desktop_frame = tk.LabelFrame(self, text="Desktop with Browser-based Front-end (Select 2)", 
                                      font=("Arial", 12), padx=10, pady=10)
        desktop_frame.pack(padx=10, pady=5, fill="x", anchor="center")
        
        # Create two dropdowns for Desktop features.
        self.desktop_var1 = tk.StringVar()
        self.desktop_var1.set("Select a Feature")
        self.desktop_var2 = tk.StringVar()
        self.desktop_var2.set("Select a Feature")
        
        lbl_d1 = tk.Label(desktop_frame, text="Feature 1:", font=("Arial", 12))
        lbl_d1.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        dropdown_d1 = tk.OptionMenu(desktop_frame, self.desktop_var1, *self.options)
        dropdown_d1.config(font=("Arial", 12))
        dropdown_d1.grid(row=0, column=1, padx=5, pady=5)
        
        lbl_d2 = tk.Label(desktop_frame, text="Feature 2:", font=("Arial", 12))
        lbl_d2.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        dropdown_d2 = tk.OptionMenu(desktop_frame, self.desktop_var2, *self.options)
        dropdown_d2.config(font=("Arial", 12))
        dropdown_d2.grid(row=1, column=1, padx=5, pady=5)
        
        # Tablet section: allows for three security features.
        tablet_frame = tk.LabelFrame(self, text="Tablet for Field Sales (Select 3)", 
                                     font=("Arial", 12), padx=10, pady=10)
        tablet_frame.pack(padx=10, pady=5, fill="x", anchor="center")
        
        # Create three dropdowns for Tablet features.
        self.tablet_var1 = tk.StringVar()
        self.tablet_var1.set("Select a Feature")
        self.tablet_var2 = tk.StringVar()
        self.tablet_var2.set("Select a Feature")
        self.tablet_var3 = tk.StringVar()
        self.tablet_var3.set("Select a Feature")
        
        lbl_t1 = tk.Label(tablet_frame, text="Feature 1:", font=("Arial", 12))
        lbl_t1.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        dropdown_t1 = tk.OptionMenu(tablet_frame, self.tablet_var1, *self.options)
        dropdown_t1.config(font=("Arial", 12))
        dropdown_t1.grid(row=0, column=1, padx=5, pady=5)
        
        lbl_t2 = tk.Label(tablet_frame, text="Feature 2:", font=("Arial", 12))
        lbl_t2.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        dropdown_t2 = tk.OptionMenu(tablet_frame, self.tablet_var2, *self.options)
        dropdown_t2.config(font=("Arial", 12))
        dropdown_t2.grid(row=1, column=1, padx=5, pady=5)
        
        lbl_t3 = tk.Label(tablet_frame, text="Feature 3:", font=("Arial", 12))
        lbl_t3.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        dropdown_t3 = tk.OptionMenu(tablet_frame, self.tablet_var3, *self.options)
        dropdown_t3.config(font=("Arial", 12))
        dropdown_t3.grid(row=2, column=1, padx=5, pady=5)
        
        # Navigation Frame: Using our custom NavigationFrame placed with place()
        self.nav_frame = NavigationFrame(self, controller)
        
    def save_responses(self):
        answers = {
            "Desktop Feature 1": self.desktop_var1.get(),
            "Desktop Feature 2": self.desktop_var2.get(),
            "Tablet Feature 1": self.tablet_var1.get(),
            "Tablet Feature 2": self.tablet_var2.get(),
            "Tablet Feature 3": self.tablet_var3.get()
        }
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page B3: Incident Response Ordering with Drag and Drop
# -----------------------------
class B3Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B3"
        title = tk.Label(self, text="B3. Place the incident response activities in the correct order.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="Drag and drop the items to reorder them.", font=("Arial", 12))
        info.pack(pady=5)

        self.activities = ["Preparation", "Detection", "Analysis", "Containment", "Eradication", "Recovery", "Lessons learned"]
        random.shuffle(self.activities)
        self.listbox = tk.Listbox(self, font=("Arial", 12), height=7, width=40, justify="center")
        self.listbox.pack(pady=10)
        for item in self.activities:
            self.listbox.insert(tk.END, item)

        # Bind mouse events for drag and drop
        self.listbox.bind('<ButtonPress-1>', self.on_start_drag)
        self.listbox.bind('<B1-Motion>', self.on_drag_motion)
        self.listbox.bind('<ButtonRelease-1>', self.on_drop)
        
        # Dictionary to hold drag data
        self.drag_data = {"item_index": None, "item_text": ""}
        
        self.nav_frame = NavigationFrame(self, controller)
    
    def on_start_drag(self, event):
        # Record the index and text of the item to be dragged.
        index = self.listbox.nearest(event.y)
        self.drag_data["item_index"] = index
        self.drag_data["item_text"] = self.listbox.get(index)
    
    def on_drag_motion(self, event):
        # Get the potential drop index and provide visual feedback.
        drop_index = self.listbox.nearest(event.y)
        self.listbox.selection_clear(0, tk.END)
        self.listbox.selection_set(drop_index)
    
    def on_drop(self, event):
        # Determine the drop index.
        drop_index = self.listbox.nearest(event.y)
        orig_index = self.drag_data["item_index"]
        if drop_index != orig_index:
            # Remove the item from its original position.
            self.listbox.delete(orig_index)
            # Insert the dragged item at the new position.
            self.listbox.insert(drop_index, self.drag_data["item_text"])
        # Clear selection and reset drag data.
        self.listbox.selection_clear(0, tk.END)
        self.drag_data = {"item_index": None, "item_text": ""}
    
    def save_responses(self):
        ordered = self.listbox.get(0, tk.END)
        self.controller.responses[self.page_id] = list(ordered)


# -----------------------------
# Page B4: Security Technology Matching
# -----------------------------
class B4Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B4"
        title = tk.Label(self, text="B4. Match the security technology to the implementation.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each implementation, select the appropriate technology.", font=("Arial", 12))
        info.pack(pady=5)

        self.implementations = [
            "Store a password on an authentication server",
            "Verify a sender’s identity",
            "Authenticate the server sending an email",
            "Store keys with a third-party",
            "Prevent data corruption when a system fails",
            "Modify a script to make it difficult to understand"
        ]
        self.options = ["Hashing", "Digital signature", "SPF", "Key escrow", "Journaling", "Obfuscation"]
        self.vars = []
        for idx, impl in enumerate(self.implementations):
            frame = tk.Frame(self)
            frame.pack(pady=5, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {impl}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select a Technology")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"B4_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page B5: Data State Selection
# -----------------------------
class B5Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B5"
        title = tk.Label(self, text="B5. Select the data state that best fits the description.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each scenario, choose: Data in-transit, Data at-rest, or Data in-use.", font=("Arial", 12))
        info.pack(pady=5)

        self.scenarios = [
            "All switches in a data center are connected with an 802.1Q trunk",
            "Sales information is uploaded daily from a remote site using a satellite network",
            "A company stores customer purchase information in a MySQL database",
            "An application decrypts credit card numbers and expiration dates to validate for approval",
            "An authentication program performs a hash of all passwords",
            "An IPS identifies a SQL injection attack and removes the attack frames from the network",
            "An automatic teller machine validates a user’s PIN before allowing a deposit",
            "Each time a spreadsheet is updated, all cells containing formulas are automatically updated",
            "All weekly backup tapes are transported to an offsite storage facility",
            "All user spreadsheets are stored on a cloud-based file sharing service"
        ]
        self.options = ["Data in-transit", "Data at-rest", "Data in-use"]
        self.vars = []
        for idx, scenario in enumerate(self.scenarios):
            frame = tk.Frame(self)
            frame.pack(pady=3, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {scenario}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select Data State")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"B5_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page C1: Firewall Traffic Flow Categorization with Image
# -----------------------------
class C1Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C1"
        title = tk.Label(self, text="C1. Categorize the following traffic flows as ALLOWED or BLOCKED.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each traffic flow, select ALLOWED or BLOCKED.", font=("Arial", 12))
        info.pack(pady=5)
        
        # IMAGE FRAME: Add an image above the response areas
        image_frame = tk.Frame(self)
        image_frame.pack(pady=10)
        try:
            self.c1_image = tk.PhotoImage(file="C1FirewallRules.png")
            # Adjust subsample factor as needed for scaling
            self.c1_image = self.c1_image.subsample(2, 2)
            img_label = tk.Label(image_frame, image=self.c1_image)
            img_label.pack(expand=True)
        except Exception as e:
            img_label = tk.Label(image_frame, text="Image C1FirewallRules.png not found", font=("Arial", 12))
            img_label.pack(expand=True)
        
        # Create response areas for each flow
        self.flows = [
            "Use a secure terminal to connect to 10.1.10.88",
            "Share the desktop on server 10.1.10.120",
            "Perform a DNS query from 10.1.10.88 to 9.9.9.9",
            "View web pages on 10.1.10.120",
            "Authenticate to an LDAP server at 10.1.10.61",
            "Synchronize the clock on a server at 10.1.10.17"
        ]
        self.options = ["ALLOWED", "BLOCKED"]
        self.vars = []
        for idx, flow in enumerate(self.flows):
            frame = tk.Frame(self)
            frame.pack(pady=3, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {flow}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C1_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page C2: Matching Device to Description (Modified)
# -----------------------------
class C2Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C2"
        title = tk.Label(self, text="C2. Match the device to the description.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each description, select the appropriate device.", font=("Arial", 12))
        info.pack(pady=5)

        # Keep only the first five descriptions (removing questions 6-11)
        self.descriptions = [
            "Block SQL injection over an Internet connection",
            "Intercept all browser requests and cache the results",
            "Forward packets between separate VLANs",
            "Configure a group of redundant web servers",
            "Evaluate the input to a browser-based application"
        ]
        # Updated options list with eight total options
        self.options = ["WAF", "Proxy Server", "Load Balancer", "Sensor", "MDM Router", "Jump Server", "IPS", "Router"]
        
        self.vars = []
        for idx, desc in enumerate(self.descriptions):
            frame = tk.Frame(self)
            frame.pack(pady=2, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {desc}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select a Device")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C2_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page C3: Matching Attack Type to Characteristic
# -----------------------------
class C3Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C3"
        title = tk.Label(self, text="C3. Match the attack type to the characteristic.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each characteristic, select the appropriate attack type.", font=("Arial", 12))
        info.pack(pady=5)

        self.characteristics = [
            "A website stops responding to normal requests",
            "Data is captured and retransmitted to a server",
            "The malware is designed to remain hidden on a computer system",
            "A list of passwords are attempted with a known username",
            "An email link redirects a user to a site that requests login credentials",
            "Permissions are circumvented by adding additional code as application input"
        ]
        self.options = ["DDoS", "Replay", "Rootkit", "Brute force", "Phishing", "Injection"]
        self.vars = []
        for idx, charac in enumerate(self.characteristics):
            frame = tk.Frame(self)
            frame.pack(pady=2, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {charac}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select an Attack Type")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C3_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page C4: Matching Cryptography Technology to Description
# -----------------------------
class C4Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C4"
        title = tk.Label(self, text="C4. Match the cryptography technology to the description.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each description, select the appropriate cryptography technology.", font=("Arial", 12))
        info.pack(pady=5)

        self.descriptions = [
            "Create a stronger key using multiple processes",
            "Data is hidden within another media type",
            "Different inputs create the same hash",
            "Sensitive data is hidden from view",
            "A different key is used for decryption than encryption",
            "Information is added to make a unique hash"
        ]
        self.options = ["Key stretching", "Steganography", "Collision", "Masking", "Asymmetric", "Salting"]
        self.vars = []
        for idx, desc in enumerate(self.descriptions):
            frame = tk.Frame(self)
            frame.pack(pady=2, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {desc}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select a Technology")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C4_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Page C5: Security Technologies for Scenarios
# -----------------------------
class C5Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C5"
        title = tk.Label(self, text="C5. Add the most applicable security technologies to the following scenarios.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each scenario, select the appropriate technology.", font=("Arial", 12))
        info.pack(pady=5)

        self.scenarios = [
            "A field service engineer uses their corporate laptop at coffee shops and hotels",
            "Software developers run a series of tests before deploying an application",
            "An administrator prevents employees from visiting known-malicious web sites",
            "Directly access cloud-based services from all corporate locations",
            "Users connecting to the network should use their corporate authentication credentials"
        ]
        self.options = ["VPN", "Sandboxing", "NGFW", "SD-WAN", "802.1X"]
        self.vars = []
        for idx, scenario in enumerate(self.scenarios):
            frame = tk.Frame(self)
            frame.pack(pady=3, anchor="center")
            lbl = tk.Label(frame, text=f"{idx+1}. {scenario}", font=("Arial", 12), wraplength=900, justify="center")
            lbl.pack(pady=2)
            var = tk.StringVar()
            var.set("Select a Technology")
            self.vars.append(var)
            dropdown = tk.OptionMenu(frame, var, *self.options)
            dropdown.config(font=("Arial", 12))
            dropdown.pack(pady=2)
        
        self.nav_frame = NavigationFrame(self, controller)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C5_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# -----------------------------
# Main execution
# -----------------------------
if __name__ == "__main__":
    app = QuizApp()
    app.mainloop()
