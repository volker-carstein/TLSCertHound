import sys

COLOR_ENABLED = True


def banner_text():
    return (
        r"""
 _____ _      _____     _____           _       _   _                       _ 
|_   _| |    /  ___|   /  __ \         | |     | | | |                     | |
  | | | |    \ `--.    | /  \/ ___ _ __| |_    | |_| | ___  _   _ _ __   __| |
  | | | |     `--. \   | |    / _ \ '__| __|   |  _  |/ _ \| | | | '_ \ / _` |
  | | | |____/\__/ /   | \__/\  __/ |  | |_    | | | | (_) | |_| | | | | (_| |
  \_/ \_____/\____/     \____/\___|_|   \__|   \_| |_/\___/ \__,_|_| |_|\__,_|
                                                                              
            v1.0 by Volker Carstein (@volker_carstein) @ 2026
        """
    )


def set_color_enabled(enabled: bool):
    global COLOR_ENABLED
    COLOR_ENABLED = enabled


def colorize(message: str, color: str):
    if not COLOR_ENABLED:
        return message
    return f"{color}{message}\033[0m"


def log_message(message: str, verbose: bool, force: bool = False):
    if not (verbose or force):
        return
    if message.startswith("[!]"):
        message = colorize(message, "\033[31m")
    elif message.startswith("[*]"):
        message = colorize(message, "\033[36m")
    print(message, file=sys.stderr)
