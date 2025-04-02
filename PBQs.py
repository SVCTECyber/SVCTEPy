import tkinter as tk
from tkinter import messagebox
import random

class QuizApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Performance-Based Questions Quiz")
        self.geometry("1920x1080")
        self.pages = []
        self.current_page_index = 0
        self.responses = {}  # dictionary to store responses
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
        if self.current_page_index < len(self.pages) - 1:
            self.show_page(self.current_page_index + 1)
        else:
            self.finish_quiz()

    def prev_page(self):
        if self.current_page_index > 0:
            self.show_page(self.current_page_index - 1)

    def finish_quiz(self):
        result = "Quiz Completed! Your responses:\n\n"
        for key, value in self.responses.items():
            result += f"{key}: {value}\n"
        messagebox.showinfo("Results", result)
        self.destroy()


# =============================
# Page A1: Matching Attack Types (with 5 sub-questions)
# =============================
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
        
        self.nav_frame = NavigationFrame(self, controller)
        self.nav_frame.pack(side="bottom", fill="x", pady=20)

    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"A1_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page A2: Security Controls for Locations (numbered with bold instruction)
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for location, var_list in self.vars.items():
            responses = [var.get() for var in var_list]
            answers[location] = responses
        self.controller.responses[self.page_id] = answers


# =============================
# Page A3: Security Category Selection (with extra bold instruction)
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"A3_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page A4: Authentication Factor Matching (with extra bold instruction)
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"A4_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


class A5Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "A5"
        
        # Title and info
        title = tk.Label(self, text="A5. Configure the following stateful firewall rules.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="Enter the rule details using the dropdown menus below.", font=("Arial", 12))
        info.pack(pady=5)
        
        # Three bullet prompt for the rules
        prompt_text = ("• Block HTTP sessions between the Web Server and the Database Server\n"
                       "• Allow the Storage Server to transfer files to the Video Server over HTTPS\n"
                       "• Allow the Management Server to use a secure terminal on the File Server")
        prompt_lbl = tk.Label(self, text=prompt_text, font=("Arial", 12), justify="left")
        prompt_lbl.pack(pady=5)
        
        # Container frame for main content and navigation
        container_frame = tk.Frame(self)
        container_frame.pack(fill="both", expand=True)
        
        # Main frame for table and image
        main_frame = tk.Frame(container_frame)
        main_frame.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        
        # Left frame: Table layout
        table_frame = tk.Frame(main_frame)
        table_frame.pack(side="left", fill="both", expand=True)
        
        headers = ["Rule#", "Source IP", "Destination IP", "Protocol (TCP/UDP)", "Port #", "Allow/Block"]
        for col, header in enumerate(headers):
            lbl = tk.Label(table_frame, text=header, font=("Arial", 12, "bold"), borderwidth=1, relief="solid", padx=5, pady=5)
            lbl.grid(row=0, column=col, sticky="nsew")
        
        ip_options = ["10.1.1.3", "10.1.1.7", "10.2.1.33", "10.2.1.47", "10.2.1.20"]
        protocol_options = ["TCP", "UDP"]
        port_options = ["80", "443", "22"]
        allow_options = ["Allow", "Block"]
        
        self.table_vars = []  # list to hold row variable dictionaries
        # Create exactly 3 data rows
        for i in range(3):
            row_vars = {}
            # Rule number label
            rule_lbl = tk.Label(table_frame, text=str(i+1), font=("Arial", 12), borderwidth=1, relief="solid", padx=5, pady=5)
            rule_lbl.grid(row=i+1, column=0, sticky="nsew")
            # Source IP
            var_source = tk.StringVar()
            var_source.set("Select")
            row_vars["Source IP"] = var_source
            opt_source = tk.OptionMenu(table_frame, var_source, *ip_options)
            opt_source.config(font=("Arial", 12))
            opt_source.grid(row=i+1, column=1, sticky="nsew", padx=2, pady=2)
            # Destination IP
            var_dest = tk.StringVar()
            var_dest.set("Select")
            row_vars["Destination IP"] = var_dest
            opt_dest = tk.OptionMenu(table_frame, var_dest, *ip_options)
            opt_dest.config(font=("Arial", 12))
            opt_dest.grid(row=i+1, column=2, sticky="nsew", padx=2, pady=2)
            # Protocol
            var_protocol = tk.StringVar()
            var_protocol.set("Select")
            row_vars["Protocol"] = var_protocol
            opt_protocol = tk.OptionMenu(table_frame, var_protocol, *protocol_options)
            opt_protocol.config(font=("Arial", 12))
            opt_protocol.grid(row=i+1, column=3, sticky="nsew", padx=2, pady=2)
            # Port #
            var_port = tk.StringVar()
            var_port.set("Select")
            row_vars["Port"] = var_port
            opt_port = tk.OptionMenu(table_frame, var_port, *port_options)
            opt_port.config(font=("Arial", 12))
            opt_port.grid(row=i+1, column=4, sticky="nsew", padx=2, pady=2)
            # Allow/Block
            var_allow = tk.StringVar()
            var_allow.set("Select")
            row_vars["Allow/Block"] = var_allow
            opt_allow = tk.OptionMenu(table_frame, var_allow, *allow_options)
            opt_allow.config(font=("Arial", 12))
            opt_allow.grid(row=i+1, column=5, sticky="nsew", padx=2, pady=2)
            
            self.table_vars.append(row_vars)
        
        # Right frame: Image space (scaled down)
        right_frame = tk.Frame(main_frame, width=300, height=400)
        right_frame.pack(side="right", fill="both", expand=False, padx=10, pady=10)
        try:
            self.firewall_image = tk.PhotoImage(file="A4Firewall.png")
            # Scale down the image if it's too big (adjust subsample factors as needed)
            self.firewall_image = self.firewall_image.subsample(2, 2)
            img_label = tk.Label(right_frame, image=self.firewall_image)
            img_label.pack(expand=True)
        except Exception as e:
            img_label = tk.Label(right_frame, text="Image A4Firewall.png\nnot found", font=("Arial", 12))
            img_label.pack(expand=True)
        
        # Navigation frame: Place at bottom of container_frame so it's always visible.
        self.nav_frame = NavigationFrame(self, controller)
        self.nav_frame.pack(in_=container_frame, side="bottom", fill="x", pady=20)
    
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


# =============================
# Page B1: Certificate Characteristic Matching
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"B1_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page B2: Security Features for Mobile App Deployment
# =============================
class B2Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B2"
        title = tk.Label(self, text="B2. Select the best security features for each platform.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="Choose the appropriate security feature(s) from the list for each platform.", font=("Arial", 12))
        info.pack(pady=5)

        self.options = ["Anti-malware", "MDM integration", "Full device encryption", "Biometric authentication", "Host-based firewall", "Infrared sensors", "OSINT"]

        desktop_frame = tk.LabelFrame(self, text="Desktop with Browser-based Front-end", font=("Arial", 12), padx=10, pady=10)
        desktop_frame.pack(padx=10, pady=5, fill="x", anchor="center")
        lbl_desktop = tk.Label(desktop_frame, text="Select security feature:", font=("Arial", 12))
        lbl_desktop.pack(pady=2)
        self.desktop_var = tk.StringVar()
        self.desktop_var.set("Select a Feature")
        dropdown_desktop = tk.OptionMenu(desktop_frame, self.desktop_var, *self.options)
        dropdown_desktop.config(font=("Arial", 12))
        dropdown_desktop.pack(pady=2)

        tablet_frame = tk.LabelFrame(self, text="Tablet for Field Sales", font=("Arial", 12), padx=10, pady=10)
        tablet_frame.pack(padx=10, pady=5, fill="x", anchor="center")
        lbl_tablet = tk.Label(tablet_frame, text="Select primary feature:", font=("Arial", 12))
        lbl_tablet.grid(row=0, column=0, padx=5, pady=2)
        self.tablet_var1 = tk.StringVar()
        self.tablet_var1.set("Select a Feature")
        dropdown_tablet1 = tk.OptionMenu(tablet_frame, self.tablet_var1, *self.options)
        dropdown_tablet1.config(font=("Arial", 12))
        dropdown_tablet1.grid(row=0, column=1, padx=5, pady=2)
        lbl_tablet2 = tk.Label(tablet_frame, text="Select secondary feature:", font=("Arial", 12))
        lbl_tablet2.grid(row=1, column=0, padx=5, pady=2)
        self.tablet_var2 = tk.StringVar()
        self.tablet_var2.set("Select a Feature")
        dropdown_tablet2 = tk.OptionMenu(tablet_frame, self.tablet_var2, *self.options)
        dropdown_tablet2.config(font=("Arial", 12))
        dropdown_tablet2.grid(row=1, column=1, padx=5, pady=2)
        lbl_tablet3 = tk.Label(tablet_frame, text="Select tertiary feature:", font=("Arial", 12))
        lbl_tablet3.grid(row=2, column=0, padx=5, pady=2)
        self.tablet_var3 = tk.StringVar()
        self.tablet_var3.set("Select a Feature")
        dropdown_tablet3 = tk.OptionMenu(tablet_frame, self.tablet_var3, *self.options)
        dropdown_tablet3.config(font=("Arial", 12))
        dropdown_tablet3.grid(row=2, column=1, padx=5, pady=2)

        self.nav_frame = NavigationFrame(self, controller)
        self.nav_frame.pack(side="bottom", fill="x", pady=20)

    def save_responses(self):
        answers = {
            "Desktop Feature": self.desktop_var.get(),
            "Tablet Primary Feature": self.tablet_var1.get(),
            "Tablet Secondary Feature": self.tablet_var2.get(),
            "Tablet Tertiary Feature": self.tablet_var3.get()
        }
        self.controller.responses[self.page_id] = answers


# =============================
# Page B3: Incident Response Ordering
# =============================
class B3Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "B3"
        title = tk.Label(self, text="B3. Place the incident response activities in the correct order.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="Use the Up and Down buttons to reorder the items.", font=("Arial", 12))
        info.pack(pady=5)

        self.activities = ["Preparation", "Detection", "Analysis", "Containment", "Eradication", "Recovery", "Lessons learned"]
        random.shuffle(self.activities)
        self.listbox = tk.Listbox(self, font=("Arial", 12), height=7, width=40, justify="center")
        self.listbox.pack(pady=10)
        for item in self.activities:
            self.listbox.insert(tk.END, item)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        up_btn = tk.Button(btn_frame, text="Up", command=self.move_up, font=("Arial", 12))
        up_btn.pack(side="left", padx=5)
        down_btn = tk.Button(btn_frame, text="Down", command=self.move_down, font=("Arial", 12))
        down_btn.pack(side="left", padx=5)

        self.nav_frame = NavigationFrame(self, controller)
        self.nav_frame.pack(side="bottom", fill="x", pady=20)

    def move_up(self):
        index = self.listbox.curselection()
        if not index:
            return
        index = index[0]
        if index == 0:
            return
        text = self.listbox.get(index)
        self.listbox.delete(index)
        self.listbox.insert(index-1, text)
        self.listbox.selection_set(index-1)

    def move_down(self):
        index = self.listbox.curselection()
        if not index:
            return
        index = index[0]
        if index == self.listbox.size()-1:
            return
        text = self.listbox.get(index)
        self.listbox.delete(index)
        self.listbox.insert(index+1, text)
        self.listbox.selection_set(index+1)

    def save_responses(self):
        ordered = self.listbox.get(0, tk.END)
        self.controller.responses[self.page_id] = list(ordered)


# =============================
# Page B4: Security Technology Matching
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"B4_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page B5: Data State Selection
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"B5_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page C1: Firewall Traffic Flow Categorization
# =============================
class C1Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C1"
        title = tk.Label(self, text="C1. Categorize the following traffic flows as ALLOWED or BLOCKED.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each traffic flow, select ALLOWED or BLOCKED.", font=("Arial", 12))
        info.pack(pady=5)

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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C1_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page C2: Matching Device to Description
# =============================
class C2Page(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.page_id = "C2"
        title = tk.Label(self, text="C2. Match the device to the description.", font=("Arial", 14), wraplength=900)
        title.pack(pady=10)
        info = tk.Label(self, text="For each description, select the appropriate device. Options: IPS, Proxy, Router, Load balancer, WAF", font=("Arial", 12))
        info.pack(pady=5)

        self.descriptions = [
            "Block SQL injection over an Internet connection",
            "Intercept all browser requests and cache the results",
            "Forward packets between separate VLANs",
            "Configure a group of redundant web servers",
            "Evaluate the input to a browser-based application",
            "A website stops responding to normal requests",
            "Data is captured and retransmitted to a server",
            "The malware is designed to remain hidden on a computer system",
            "A list of passwords are attempted with a known username",
            "An email link redirects a user to a site that requests login credentials",
            "Permissions are circumvented by adding additional code as application input"
        ]
        self.options = ["IPS", "Proxy", "Router", "Load balancer", "WAF"]
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C2_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page C3: Matching Attack Type to Characteristic
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C3_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page C4: Matching Cryptography Technology to Description
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C4_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Page C5: Security Technologies for Scenarios
# =============================
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
        self.nav_frame.pack(side="bottom", fill="x", pady=20)
        
    def save_responses(self):
        answers = {}
        for idx, var in enumerate(self.vars):
            answers[f"C5_Q{idx+1}"] = var.get()
        self.controller.responses[self.page_id] = answers


# =============================
# Navigation Frame used in every page
# =============================
class NavigationFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        prev_btn = tk.Button(self, text="Previous", command=self.go_prev, font=("Arial", 12))
        prev_btn.pack(side="left", padx=20)
        next_btn = tk.Button(self, text="Next", command=self.go_next, font=("Arial", 12))
        next_btn.pack(side="right", padx=20)

    def go_next(self):
        self.controller.pages[self.controller.current_page_index].save_responses()
        self.controller.next_page()

    def go_prev(self):
        self.controller.pages[self.controller.current_page_index].save_responses()
        self.controller.prev_page()


if __name__ == "__main__":
    app = QuizApp()
    app.mainloop()
