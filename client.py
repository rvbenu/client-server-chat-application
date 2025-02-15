import tkinter as tk
from tkinter import messagebox, ttk
import threading
import subprocess
import queue
import json  # for JSON parsing
import sys

DELIMITER = "\x1F"  # Unit separator used by the protocol

class ChatClientGUI:
    def __init__(self, root, server_ip, port):
        """
        Initialize the Chat Client GUI.

        This constructor sets up the main GUI window, starts the client subprocess,
        creates the necessary queues for communication between the client process and
        the GUI, and initiates the login window.

        Args:
            root (tk.Tk): The root tkinter window.
            server_ip (str): The server IP address.
            port (int or str): The port number to connect to.
        """
        self.root = root
        self.root.title("Chat Client")
        self.server_ip = server_ip
        self.port = port

        # Queue for handling output lines from the client process (each expected to be a JSON string or system message)
        self.queue = queue.Queue()
        
        # Start the client process (adjust the binary path as needed)
        self.client_process = subprocess.Popen(
            ["./client", self.server_ip, str(self.port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        # List to hold all chat message objects (each is a dict)
        self.messages = []
        
        # Schedule the process_queue routine to check the output queue periodically.
        self.root.after(100, self.process_queue)

        # Display the login/register window initially.
        self.login_window()

        # Start a background thread to read lines from the client process stdout.
        self.reader_thread = threading.Thread(target=self.read_from_client, daemon=True)
        self.reader_thread.start()

    def login_window(self):
        """
        Display the login/register window.

        This method destroys any existing widgets in the root window and creates a new frame
        that contains entry fields for username and password as well as radio buttons for selecting
        login or registration mode.
        """
        # Remove all existing widgets from the root window.
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create a new frame for the login interface.
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(pady=20)

        # Create and place the username label and entry field.
        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)

        # Create and place the password label and entry field.
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)

        # Radio buttons to choose between Login and Register.
        self.auth_mode = tk.StringVar(value="L")
        tk.Radiobutton(self.login_frame, text="Login", variable=self.auth_mode, value="L").grid(row=2, column=0)
        tk.Radiobutton(self.login_frame, text="Register", variable=self.auth_mode, value="R").grid(row=2, column=1)

        # Button to submit the credentials.
        self.submit_button = tk.Button(self.login_frame, text="Proceed", command=self.send_authentication)
        self.submit_button.grid(row=3, column=0, columnspan=2, pady=10)

    def send_authentication(self):
        """
        Send login or registration credentials to the server.

        This method collects the username, password, and authentication mode (login or register)
        from the GUI fields, constructs a command string using the delimiter, and sends it to the
        client process.
        """
        username = self.username_entry.get()
        password = self.password_entry.get()
        mode = self.auth_mode.get()
        if username and password:
            # Construct the command string with the protocol's delimiter.
            command = f"{mode}{DELIMITER}{username}{DELIMITER}{password}"
            self.send_to_client(command)
        else:
            messagebox.showerror("Error", "Username and Password required!")

    def open_main_window(self):
        """
        Create the main chat interface after successful authentication.

        This method destroys the login window and builds the main chat layout with a left pane
        (for user search and offline message retrieval), a center pane (for displaying chat messages
        and sending new messages), and a right pane (for deletion and account controls).
        """
        # Destroy the login window.
        self.login_frame.destroy()

        # Create left, center, and right frames for the chat interface.
        self.left_frame = tk.Frame(self.root, width=200)
        self.left_frame.pack(side=tk.LEFT, padx=10, fill=tk.Y)

        self.center_frame = tk.Frame(self.root)
        self.center_frame.pack(side=tk.LEFT, padx=10, fill=tk.BOTH, expand=True)

        self.right_frame = tk.Frame(self.root, width=200)
        self.right_frame.pack(side=tk.RIGHT, padx=10, fill=tk.Y)

        # LEFT PANE: User search and offline messages.
        tk.Label(self.left_frame, text="Search Users:").pack()
        self.search_entry = tk.Entry(self.left_frame)
        self.search_entry.pack()
        self.search_button = tk.Button(self.left_frame, text="Search", command=self.search_users)
        self.search_button.pack()

        tk.Label(self.left_frame, text="User List:").pack(pady=(5, 0))
        self.user_listbox = tk.Listbox(self.left_frame, height=10)
        self.user_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        tk.Label(self.left_frame, text="Retrieve Offline Messages:").pack(pady=(10, 0))
        self.receive_spinbox = tk.Spinbox(self.left_frame, from_=1, to=100, width=5)
        self.receive_spinbox.pack()
        self.receive_button = tk.Button(self.left_frame, text="Retrieve", command=self.receive_messages)
        self.receive_button.pack(pady=(5, 10))

        # CENTER PANE: Chat messages and sending new messages.
        chat_list_frame = tk.Frame(self.center_frame)
        chat_list_frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(chat_list_frame, text="Chat Messages:").pack(anchor="w")
        self.message_listbox = tk.Listbox(chat_list_frame, height=15, font=("Courier", 10), width=80)
        self.message_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_scrollbar = tk.Scrollbar(chat_list_frame)
        self.message_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.message_listbox.config(yscrollcommand=self.message_scrollbar.set)
        self.message_scrollbar.config(command=self.message_listbox.yview)

        send_frame = tk.Frame(self.center_frame)
        send_frame.pack(fill=tk.X, pady=10)
        tk.Label(send_frame, text="Recipient:").grid(row=0, column=0, sticky="w", padx=5)
        self.recipient_entry = tk.Entry(send_frame, width=50)
        self.recipient_entry.grid(row=0, column=1, sticky="ew", padx=5)
        tk.Label(send_frame, text="Message:").grid(row=1, column=0, sticky="w", padx=5, pady=(5, 0))
        self.message_entry = tk.Entry(send_frame, width=50)
        self.message_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=(5, 0))
        self.send_button = tk.Button(send_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        send_frame.columnconfigure(1, weight=1)

        # RIGHT PANE: Message deletion and account controls.
        # Top part for deleting messages.
        top_right_frame = tk.Frame(self.right_frame)
        top_right_frame.pack(side=tk.TOP, fill=tk.X, pady=(10, 10))
        tk.Label(top_right_frame, text="Delete Selected Message:").pack(pady=(0, 5))
        self.delete_button = tk.Button(top_right_frame, text="Delete", command=self.delete_message)
        self.delete_button.pack()

        # Bottom part for account information and controls.
        bottom_right_frame = tk.Frame(self.right_frame)
        bottom_right_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        # Display the current username.
        self.account_label = tk.Label(bottom_right_frame, text=f"Logged in as: {self.current_user}")
        self.account_label.pack(pady=(0, 5))
        # Log Out button.
        self.logout_button = tk.Button(bottom_right_frame, text="Log Out", command=self.logout)
        self.logout_button.pack(side=tk.LEFT, padx=5)
        # Delete Account button.
        self.delete_account_button = tk.Button(bottom_right_frame, text="Delete Account", command=self.delete_account)
        self.delete_account_button.pack(side=tk.LEFT, padx=5)

        # Request chat history immediately after opening the main window.
        self.request_history()

    def request_history(self):
        """
        Request the message history for the current user.

        This method sends a command to the client process to retrieve the chat history.
        The command uses the 'h' op code followed by the username.
        """
        command = f"h{DELIMITER}{self.current_user}"
        self.send_to_client(command)
        
    def send_to_client(self, message):
        """
        Send a command to the client process.

        This method writes the command message to the client process's stdin,
        ensuring it is properly flushed to be processed immediately.

        Args:
            message (str): The command string to send.
        """
        try:
            self.client_process.stdin.write(message + "\n")
            self.client_process.stdin.flush()
        except BrokenPipeError:
            messagebox.showerror("Error", "Client connection lost.")

    def search_users(self):
        """
        Send a user search command to the client process.

        This method retrieves the search term from the search entry field,
        constructs the appropriate command with the 'l' op code, and sends it.
        """
        search_term = self.search_entry.get()
        if search_term:
            command = f"l{DELIMITER}{search_term}"
            self.send_to_client(command)

    def send_message(self):
        """
        Send a chat message to the server.

        This method collects the sender, recipient, and message text,
        constructs a command string with the 's' op code, and sends it to the client process.
        After sending, it clears the message entry field.
        """
        sender = self.current_user
        recipient = self.recipient_entry.get()
        message = self.message_entry.get()
        if recipient and message:
            command = f"s{DELIMITER}{sender}{DELIMITER}{recipient}{DELIMITER}{message}"
            self.send_to_client(command)
            self.message_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Recipient and Message required!")

    def delete_message(self):
        """
        Delete the selected message by sending a delete command.

        This method retrieves the selected message from the listbox,
        extracts its message_id, constructs a command with the 'd' op code,
        and sends it to the client process. It then removes the message from
        both the listbox and the internal messages list.
        """
        selection = self.message_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a message to delete.")
            return
        index = selection[0]
        message_obj = self.messages[index]
        message_id = message_obj.get("message_id")
        command = f"d{DELIMITER}{self.current_user}{DELIMITER}{message_id}"
        self.send_to_client(command)
        self.message_listbox.delete(index)
        del self.messages[index]

    def logout(self):
        """
        Log out the user and return to the login page.

        This method sends the 'q' (quit) command to the client process,
        terminates the client process, destroys all widgets, and then reinitializes the GUI.
        """
        self.send_to_client("q")
        self.client_process.terminate()
        for widget in self.root.winfo_children():
            widget.destroy()
        self.__init__(self.root, self.server_ip, self.port)

    def delete_account(self):
        """
        Delete the user's account from the server and log out.

        This method constructs a command with the 'D' op code (account deletion),
        sends it to the client process, and then the account deletion confirmation
        will be handled via the output stream.
        """
        command = f"D{DELIMITER}{self.current_user}"
        self.send_to_client(command)

    def receive_messages(self):
        """
        Retrieve offline messages from the server.

        This method obtains the number of messages to retrieve from the spinbox,
        validates it, and sends a command with the 'r' op code along with the count.
        """
        try:
            num = int(self.receive_spinbox.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")
            return
        if num <= 0:
            messagebox.showerror("Error", "Please enter a positive number.")
            return
        if hasattr(self, "current_user"):
            command = f"r{DELIMITER}{self.current_user}{DELIMITER}{num}"
            self.send_to_client(command)
        else:
            messagebox.showerror("Error", "No user is logged in.")

    def read_from_client(self):
        """
        Continuously read lines from the client process stdout and enqueue them.

        This background thread reads each line from the client process's output.
        Each line is expected to be a JSON-formatted string or a system message.
        The read lines are placed into the queue for processing in the main thread.
        """
        while True:
            output = self.client_process.stdout.readline()
            if output:
                self.queue.put(output.strip())
                # Schedule the queue processing to run in the main thread.
                self.root.after(100, self.process_queue)
            else:
                break

    def process_queue(self):
        """
        Process messages from the output queue.

        This method checks each message in the queue and determines whether it is a
        system message or a JSON formatted message. Based on the content, it updates
        the GUI accordingly.
        """
        while not self.queue.empty():
            message = self.queue.get()
            print("[DEBUG] Message buffered:", message)
            # Check for a specific system message indicating authentication success.
            if message == "[CLIENT] Authentication successful.":
                self.current_user = self.username_entry.get()
                self.open_main_window()
                continue
            # Process the user list response message.
            elif message.startswith("[CLIENT] User list from server:"):
                parts = message.split(":", 1)
                if len(parts) > 1:
                    user_list_str = parts[1].strip()
                    usernames = [name.strip() for name in user_list_str.split(",") if name.strip()]
                    if hasattr(self, "user_listbox"):
                        self.user_listbox.delete(0, tk.END)
                        for username in usernames:
                            self.user_listbox.insert(tk.END, username)
                continue
            # If the message does not appear to be JSON, print it as a system message.
            elif not message.startswith("{"):
                print("[SYSTEM]", message)
                continue
    
            try:
                # Attempt to parse the message as JSON.
                data = json.loads(message)
            except Exception as e:
                print("Error parsing JSON:", e)
                continue
    
            # Handle account deletion confirmation.
            if data.get("type") == "account_deleted":
                print("[DEBUG] Account deletion confirmed.")
                self.logout()
                continue
    
            # Handle chat and history messages.
            if data.get("type") in ("chat", "history"):
                self.messages.append(data)
                display_str = f"[{data.get('sender')}][{data.get('message_id')}]: {data.get('content')}"
                # Right-align messages sent by the current user.
                if data.get("sender") == self.current_user:
                    display_str = display_str.rjust(80)
                self.message_listbox.insert(tk.END, display_str)
            # Handle confirmation messages.
            elif data.get("type") == "confirmation":
                self.messages.append(data)
                display_str = f"[{data.get('recipient')}][{data.get('message_id')}]: {data.get('content')}"
                display_str = display_str.rjust(80)
                self.message_listbox.insert(tk.END, display_str)
            # Handle deletion notifications.
            elif data.get("type") == "delete":
                del_id = data.get("message_id")
                for idx, msg in enumerate(self.messages):
                    if msg.get("message_id") == del_id:
                        self.message_listbox.delete(idx)
                        del self.messages[idx]
                        print(f"[DEBUG] Deleted message {del_id} from listbox.")
                        break
            else:
                print("[SYSTEM JSON]", data)

    def quit_client(self):
        """
        Send a quit command, terminate the client process, and exit the application.

        This method is used to gracefully shut down the client when quitting.
        """
        self.send_to_client("q")
        self.client_process.terminate()
        self.root.quit()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <server_ip> <port>")
        sys.exit(1)
    server_ip = sys.argv[1]
    port = sys.argv[2]
    root = tk.Tk()
    app = ChatClientGUI(root, server_ip, port)
    root.mainloop()
