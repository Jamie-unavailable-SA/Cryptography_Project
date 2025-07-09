import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional
from sms_sender import (
    OTPRecord, EncryptedPacket,
    generate_otp, derive_key_from_otp, verify_otp,
    encrypt_message, decrypt_message, send_sms
)
from tkinter.font import Font


class SecureMessagingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Message Transfer")
        self.root.geometry("1000x800")
        self.root.minsize(900, 700)

        self.current_otp: Optional[OTPRecord] = None
        self.encrypted_packet: Optional[EncryptedPacket] = None
        self.encryption_key: Optional[bytes] = None

        self.canvas = tk.Canvas(root, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.draw_gradient('#E6E6FA', '#9370DB')

        self.main_frame = ttk.Frame(self.canvas, style='Main.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        self.configure_styles()


    def draw_gradient(self, color1, color2):
        def hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))

        r1, g1, b1 = hex_to_rgb(color1)
        r2, g2, b2 = hex_to_rgb(color2)

        steps = 100
        for i in range(steps):
            r = int(r1 + (r2 - r1) * i / steps)
            g = int(g1 + (g2 - g1) * i / steps)
            b = int(b1 + (b2 - b1) * i / steps)
            hex_color = f'#{r:02x}{g:02x}{b:02x}'
            self.canvas.create_rectangle(0, i * 8, 1000, (i + 1) * 8,
                                         outline="", fill=hex_color)

    def configure_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.primary_color = "#6A5ACD"
        self.success_color = "#4B0082"
        self.text_color = "#000000"
        self.frame_color = "#F8F8FF"
        self.dark_purple = "#4B0082"

        self.style.configure('Main.TFrame', background=self.frame_color)
        self.style.configure('TFrame', background=self.frame_color)
        self.style.configure('TLabelframe', background=self.frame_color,
                             bordercolor=self.frame_color, lightcolor=self.frame_color,
                             darkcolor=self.frame_color)
        self.style.configure('TLabelframe.Label', background=self.frame_color,
                             foreground=self.text_color, font=('Segoe UI', 11, 'bold'))

        self.style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=8)
        self.style.configure('primary.TButton', foreground='white', background=self.primary_color)
        self.style.map('primary.TButton', background=[('active', '#7B68EE'), ('disabled', '#cccccc')])

        self.style.configure('success.TButton', foreground='white', background=self.success_color)
        self.style.map('success.TButton', background=[('active', '#6A5ACD'), ('disabled', '#cccccc')])

        self.style.configure('TRadiobutton', background=self.frame_color, foreground=self.text_color,
                             font=('Segoe UI', 11))
        self.style.map('TRadiobutton', background=[('active', self.primary_color)],
                                          foreground=[('active', 'white')])

        self.style.configure('Mode.TRadiobutton', background=self.frame_color, foreground=self.text_color,
                             font=('Segoe UI', 11, 'bold'))
        self.style.map('Mode.TRadiobutton', background=[('active', self.primary_color)],
                                          foreground=[('active', 'white')])
        # Header
        self.header = tk.Label(
            self.main_frame,
            text="🔒 Secure Message Transfer",
            font=('Segoe UI', 20, 'bold'),
            fg=self.primary_color,
            bg=self.frame_color
        )
        self.header.pack(fill=tk.X, pady=(0, 20))

        self.mode_var = tk.StringVar(value="encrypt")
        mode_frame = ttk.Frame(self.main_frame)
        mode_frame.pack(fill=tk.X, pady=10)

        ttk.Radiobutton(
            mode_frame,
            text="Encrypt & Send",
            variable=self.mode_var,
            value="encrypt",
            command=self.switch_mode,
            style="Mode.TRadiobutton"
        ).pack(side=tk.LEFT, padx=15)

        ttk.Radiobutton(
            mode_frame,
            text="Decrypt",
            variable=self.mode_var,
            value="decrypt",
            command=self.switch_mode,
            style="Mode.TRadiobutton"
        ).pack(side=tk.LEFT, padx=15)

        # Encryption Frame
        self.encrypt_frame = ttk.LabelFrame(
            self.main_frame,
            text=" Encrypt & Send Message ",
            style='TLabelframe'
        )
        self.setup_encrypt_tab()

        # Decryption Frame
        self.decrypt_frame = ttk.LabelFrame(
            self.main_frame,
            text=" Decrypt Received Message ",
            style='TLabelframe'
        )
        self.setup_decrypt_tab()

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(
            self.main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg=self.dark_purple,
            fg='black',
            font=('Segoe UI', 9),
            padx=10
        )
        self.status_bar.pack(fill=tk.X, pady=(15, 0))

        # Set initial mode
        self.switch_mode()

    def setup_encrypt_tab(self):
        """Setup the encryption tab UI"""
        # Message input
        msg_frame = ttk.Frame(self.encrypt_frame)
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        tk.Label(
            msg_frame,
            text="Message to encrypt:",
            font=('Segoe UI', 10),
            fg='black',
            bg=self.frame_color
        ).pack(anchor='w')

        self.message_entry = scrolledtext.ScrolledText(
            msg_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            height=10,
            padx=10,
            pady=10,
            bg='white',
            highlightthickness=1,
            highlightbackground='#AAAAAA'
        )
        self.message_entry.pack(fill=tk.BOTH, expand=True, pady=(5, 15))

        # Recipient details
        recipient_frame = ttk.Frame(self.encrypt_frame)
        recipient_frame.pack(fill=tk.X, padx=15, pady=5)

        tk.Label(
            recipient_frame,
            text="Recipient's Phone Number (with country code):",
            font=('Segoe UI', 10),
            fg='black',
            bg=self.frame_color
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.phone_entry = ttk.Entry(
            recipient_frame,
            width=25,
            font=('Segoe UI', 10)
        )
        self.phone_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Buttons
        button_frame = ttk.Frame(self.encrypt_frame)
        button_frame.pack(fill=tk.X, padx=15, pady=15)

        self.encrypt_btn = ttk.Button(
            button_frame,
            text="Encrypt & Send",
            command=self.encrypt_and_send,
            style='primary.TButton',
            width=15
        )
        self.encrypt_btn.pack(side=tk.RIGHT)

        # Encrypted output
        output_frame = ttk.Frame(self.encrypt_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        tk.Label(
            output_frame,
            text="Encrypted Output:",
            font=('Segoe UI', 10),
            fg='black',
            bg=self.frame_color

        ).pack(anchor='w')

        self.encrypted_output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            height=8,
            state='disabled',
            padx=10,
            pady=10,
            bg='white',
            highlightthickness=1,
            highlightbackground='#AAAAAA'
        )
        self.encrypted_output.pack(fill=tk.BOTH, expand=True)

    def setup_decrypt_tab(self):
        """Setup the decryption tab UI"""
        # Encrypted message input
        msg_frame = ttk.Frame(self.decrypt_frame)
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        tk.Label(
            msg_frame,
            text="Encrypted Message:",
            font=('Segoe UI', 10),
            fg='black',
            bg=self.frame_color
        ).pack(anchor='w')

        self.encrypted_entry = scrolledtext.ScrolledText(
            msg_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            height=10,
            padx=10,
            pady=10,
            bg='white',
            highlightthickness=1,
            highlightbackground='#AAAAAA'
        )
        self.encrypted_entry.pack(fill=tk.BOTH, expand=True, pady=(5, 15))

        # OTP input
        otp_frame = ttk.Frame(self.decrypt_frame)
        otp_frame.pack(fill=tk.X, padx=15, pady=10)

        tk.Label(
            otp_frame,
            text="OTP (received via SMS):",
            font=('Segoe UI', 10),
            fg='black',
            bg=self.frame_color
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.otp_entry = ttk.Entry(
            otp_frame,
            width=15,
            font=('Consolas', 12),
            justify='center'
        )
        self.otp_entry.pack(side=tk.LEFT)

        # Buttons
        button_frame = ttk.Frame(self.decrypt_frame)
        button_frame.pack(fill=tk.X, padx=15, pady=15)

        self.decrypt_btn = ttk.Button(
            button_frame,
            text="Decrypt Message",
            command=self.decrypt_message,
            style='success.TButton',
            width=15
        )
        self.decrypt_btn.pack(side=tk.RIGHT)

        # Decrypted output
        output_frame = ttk.Frame(self.decrypt_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        tk.Label(
            output_frame,
            text="Decrypted Message:",
            font=('Segoe UI', 10),
            fg='black',
            bg=self.frame_color
        ).pack(anchor='w')

        self.decrypted_output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            height=8,
            state='disabled',
            padx=10,
            pady=10,
            bg='white',
            highlightthickness=1,
            highlightbackground='#AAAAAA'
        )
        self.decrypted_output.pack(fill=tk.BOTH, expand=True)

    def switch_mode(self):
        """Switch between encrypt and decrypt modes"""
        if self.mode_var.get() == "encrypt":
            self.decrypt_frame.pack_forget()
            self.encrypt_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        else:
            self.encrypt_frame.pack_forget()
            self.decrypt_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def update_status(self, message: str):
        """Update the status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()

    def encrypt_and_send(self):
        """Handle encryption and SMS sending"""
        message = self.message_entry.get("1.0", tk.END).strip()
        phone_number = self.phone_entry.get().strip()

        if not message:
            messagebox.showerror("Error", "Please enter a message to encrypt")
            return

        if not phone_number:
            messagebox.showerror("Error", "Please enter recipient's phone number")
            return

        self.update_status("Encrypting message...")
        self.encrypt_btn.config(state=tk.DISABLED)

        try:
            # Encrypt and store both packet and key
            packet, self.encryption_key = encrypt_message(message)
            self.encrypted_packet = packet

            # Generate OTP just for authentication
            self.current_otp = generate_otp()

            # Display the encrypted message
            self.encrypted_output.config(state='normal')
            self.encrypted_output.delete("1.0", tk.END)
            self.encrypted_output.insert("1.0", packet.to_json())
            self.encrypted_output.config(state='disabled')

            # Send OTP via SMS
            sms_message = f"Your OTP for decryption is: {self.current_otp.code}. Valid for 5 minutes."
            sms_success = send_sms(phone_number, sms_message)

            if sms_success:
                self.update_status("Message encrypted and OTP sent via SMS!")
                messagebox.showinfo("Success", "Message encrypted and OTP sent successfully!")
            else:
                self.update_status("Encryption done, but SMS failed!")
                messagebox.showwarning(
                    "SMS Error",
                    f"Could not send SMS. Your OTP is: {self.current_otp.code}"
                )

            # Switch to decrypt mode
            self.mode_var.set("decrypt")
            self.switch_mode()
            self.encrypted_entry.delete("1.0", tk.END)
            self.encrypted_entry.insert("1.0", packet.to_json())

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.update_status("Encryption failed")
        finally:
            self.encrypt_btn.config(state=tk.NORMAL)

    def decrypt_message(self):
        """Handle decryption of received message"""
        encrypted_json = self.encrypted_entry.get("1.0", tk.END).strip()
        otp_code = self.otp_entry.get().strip()

        if not encrypted_json:
            messagebox.showerror("Error", "Please enter an encrypted message")
            return

        if not otp_code or len(otp_code) != 6 or not otp_code.isdigit():
            messagebox.showerror("Error", "Please enter a valid 6-digit OTP")
            return

        self.update_status("Decrypting message...")
        self.decrypt_btn.config(state=tk.DISABLED)

        try:
            packet = EncryptedPacket.from_json(encrypted_json)

            # Verify OTP first
            if self.current_otp is None or not verify_otp(otp_code, self.current_otp):
                raise ValueError("Invalid or expired OTP")

            # Use the stored encryption key
            if self.encryption_key is None:
                raise ValueError("No encryption key found")

            plaintext = decrypt_message(packet, self.encryption_key)

            # Display decrypted message
            self.decrypted_output.config(state='normal')
            self.decrypted_output.delete("1.0", tk.END)
            self.decrypted_output.insert("1.0", plaintext)
            self.decrypted_output.config(state='disabled')

            self.update_status("Message decrypted successfully")
            messagebox.showinfo("Success", "Message decrypted successfully!")

        except ValueError as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Decryption failed - Invalid OTP")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Decryption failed")
        finally:
            self.decrypt_btn.config(state=tk.NORMAL)


if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    root = tk.Tk()
    app = SecureMessagingApp(root)
    root.mainloop()