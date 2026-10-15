# Disclaimer

## Hobby project, provided as is

**Local Website Port Scanner** is a free hobby project made for learning and for checking your own systems. It comes with no promises of any kind.

## Limitation of liability

- The software is provided **"as is"** and **"as available"**, without warranty of any kind, express or implied. This includes any warranty of quality, accuracy, reliability or fitness for a particular purpose.
- To the fullest extent allowed by law, the author and contributors are **not liable** for any damage, loss, interruption, legal issue or other problem of any kind that comes from using, or not being able to use, this software.
- You use it **at your own risk** and you are fully responsible for what you do with it.
- Results can be incomplete or wrong (for example behind a firewall or on an unusual network). A clean result does not prove that a system is secure.
- Nothing here is legal, security or professional advice.

## Use on your own systems only

Use this tool only on systems that **you own** or where you have **clear permission** to test, such as your own computer, your own local website or your own home network.

Scanning systems without permission can be against the law. Depending on your country, laws such as the Computer Fraud and Abuse Act (United States), the Computer Misuse Act (United Kingdom) or the Information Technology Act, 2000 (India) may apply. Please check the rules where you live before you scan anything.

## What the tool does

- It checks which TCP ports accept a connection.
- On open ports it sends one normal web request, or reads a short reply, to show which service is running.
- It does not change anything, log in anywhere, or send harmful data to any system.
- If you enter a public address, it shows a warning and asks you to confirm that you have permission. That confirmation is your own statement of responsibility.

## Log file

Each scan is saved in `scanner.log` on your own device: time, target, open ports and duration. The file is not sent anywhere, it rotates automatically, and it is ignored by git so it is not uploaded to GitHub by accident. You can delete it at any time.

## Problems

If you find a bug, please open an issue in the repository.

By using this software you agree to these terms.
