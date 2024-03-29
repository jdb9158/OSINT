"""
  ____             _       _   ____  _     _      _     _ 
 / ___|  ___   ___(_) __ _| | / ___|| |__ (_) ___| | __| |
 \___ \ / _ \ / __| |/ _` | | \___ \| '_ \| |/ _ \ |/ _` |
  ___) | (_) | (__| | (_| | |  ___) | | | | |  __/ | (_| |
 |____/ \___/ \___|_|\__,_|_| |____/|_| |_|_|\___|_|\__,_|
                                                          

Social Media Vulnerability Scanner

"""

import os
import lzma
import json
import subprocess
#import exiftool
import instaloader

# Only Instagram functionality as of right now
class SocialShield:
    def __init__(self):
        self.loader = instaloader.Instaloader()

    def choose_platform(self):
        print("Please choose a social media platform to scan:")
        print("1: Instagram\n2: Snapchat\n")
        choice = input("Enter your choice (1 or 2): ")
        
        if choice == '1':
            self.loader = instaloader.Instaloader()
            return 'Instagram'
        elif choice == '2':
            # Initialize Snapchat scraping setup here (if available)
            return 'Snapchat'
        else:
            print("Invalid choice. Please enter 1 or 2.")
            return self.choose_platform()

    def login(self, username, password):
        try:
            self.loader.login(username, password)
            print("Logged in successfully.")
        except instaloader.TwoFactorAuthRequiredException:
            # Two-factor authentication required
            try:
                code = input("Enter the 6-digit 2FA code: ")
                self.loader.two_factor_login(code)
                print("Logged in successfully with 2FA.")
            except instaloader.exceptions.BadCredentialsException:
                print("Invalid 2FA code. Please try again.")
            except Exception as e:
                print(f"An error occurred during 2FA login: {e}")
        except instaloader.exceptions.BadCredentialsException:
            print("Bad credentials. Please check your username and password.")
        except Exception as e:
            print(f"An error occurred during login: {e}")

    def analyze_profile(self, username):
        profile = instaloader.Profile.from_username(self.loader.context, username)

        # Ensure the directory for the profile exists and download profile
        self.loader.download_profile(username, profile_pic_only=False)

        profile_dir = os.path.join(username)
        self.process_exif(profile_dir)
        
        # Iterate over files in the profile directory
        for root, dirs, files in os.walk(profile_dir):
            for file in files:
                if file.endswith(".xz"):
                    xz_file_path = os.path.join(root, file)
                    json_file_path = xz_file_path[:-3]  # Assuming the extension is .json.xz
                    self.extract_xz_file(xz_file_path, json_file_path)

        self.process_exif(profile_dir)

    def process_exif(self, dir):
        for root, dirs, files in os.walk(dir):
            for file in files:
                if file.lower().endswith((".jpg", ".mp4")):
                    file_path = os.path.join(root, file)
                    self.extract_exif(file_path)

    def extract_exif(self, image_path):
        command = ['exiftool', image_path]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            print(f"EXIF data for {image_path}:")
            print(result.stdout)
        except Exception as e:
            print(f"Error extracting EXIF data from {image_path}: {e}")

    def process_directory_for_tagged_users(self, profile_directory):
        for root, dirs, files in os.walk(profile_directory):
            for file in files:
                if file.endswith('.json'):
                    json_file_path = os.path.join(root, file)
                    self.print_post_details(json_file_path)

    def print_post_details(self, json_file_path):
        try:
            with open(json_file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            # Navigate to the correct location based on the new structure
            if 'node' in data and 'edge_media_to_tagged_user' in data['node']:
                edges = data['node']['edge_media_to_tagged_user'].get('edges', [])
            else:
                print(f"'edge_media_to_tagged_user' not found in {json_file_path}. Here's what's available at node level: {list(data.get('node', {}).keys())}")
                return
            
            if not edges:
                print(f"No tagged users found in {json_file_path}.")
                return
            
            print(f"Tagged users (and Possible Connections) in {json_file_path}:")
            for edge in edges:
                user_info = edge.get('node', {}).get('user', {})
                full_name = user_info.get('full_name', 'N/A')
                username = user_info.get('username', 'N/A')
                print(f"  Full Name: {full_name}, Username: {username}")
    
        except FileNotFoundError:
            print(f"{json_file_path} not found.")
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {json_file_path}.")
        except Exception as e:
            print(f"Error processing {json_file_path}: {e}")

    def scan_profiles(self, usernames):
        reports = []
        for username in usernames:
            try:
                report = self.analyze_profile(username)
                reports.append(report)
            except instaloader.exceptions.ProfileNotExistsException:
                print(f"Profile {username} does not exist.")
            except instaloader.exceptions.ProfileHasNoPicsException:
                print(f"Profile {username} has no pictures.")
            except Exception as e:
                print(f"Error processing {username}: {e}")
        return reports

    def extract_xz_file(self, xz_file_path, output_path):
        try:
            with lzma.open(xz_file_path, 'rb') as f, open(output_path, 'wb') as fout:
                file_content = f.read()
                fout.write(file_content)
            print(f"Extracted {xz_file_path} to {output_path}")
        except FileNotFoundError:
            print(f"{xz_file_path} not found.")
        except Exception as e:
            print(f"Error extracting {xz_file_path}: {e}")


    def analyze_snapchat(self, username):
        # Get the directory of the currently running script
        current_script_dir = os.path.dirname(os.path.realpath(__file__))
        
        # Construct the relative path to the SnapIntel directory
        snapintel_dir = os.path.join(current_script_dir, 'SnapIntel')
        
        # Ensure the path to SnapIntel's main.py is relative to the current script's location
        snapintel_script = os.path.join(snapintel_dir, 'main.py')
        # Construct the command to run SnapIntel
        command_stats = ['python3', snapintel_script, '-u', username, '-l', 'us']
        
        try:
            # Save the current working directory
            original_cwd = os.getcwd()

            # Change the working directory to the SnapIntel directory
            os.chdir(snapintel_dir)

            
            # Execute the command
            result = subprocess.run(command_stats, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                print(f"SnapIntel executed successfully for username: {username}")
                print(result.stdout)
            else:
                print(f"SnapIntel encountered an error for username: {username}")
                print(result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error running SnapIntel for {username}: {e.stderr}")
        except Exception as e:
            print(f"Unexpected error running SnapIntel for {username}: {e}")
        finally:
            # Change back to the original working directory
            os.chdir(original_cwd)
        self.print_privacy_tips()

    def print_privacy_tips(self):
        print("\n[Privacy Tips for Snapchat Users]\n")
        
        tips = [
            "Avoid sharing your full name or initials in your Snapchat username or display name. This can make it harder for unwanted parties to identify or track you.",
            "Be cautious about listing your birthday, especially the year. Sharing your age can increase the risk of identity theft or other forms of social engineering.",
            "Consider keeping your account private. A public account can expose your snaps and stories to a broader audience than intended, increasing your digital footprint.",
            "Be mindful of the background in your snaps. Unintentionally captured details (like street signs, house numbers, or identifiable landmarks) can reveal your location.",
            "Regularly review your friend list and privacy settings. Snapchat updates its features and settings, so it's a good practice to ensure your privacy preferences are up-to-date.",
            "Think twice before sharing snaps that could reveal routines or habits. Information about your daily activities can be pieced together over time to predict your movements.",
            "Use the blocking and reporting features to manage who can see your content and interact with you. Snapchat allows you to block users who you do not wish to share information with or who behave inappropriately.",
            "Educate yourself on the latest social engineering tactics. Scammers and hackers often use social media to gather personal information for fraudulent purposes."
        ]
        
        for tip in tips:
            print(f"• {tip}\n")
        
        print("Remember, the key to maintaining privacy on social media is to share wisely. It's not just about what you share, but also who you share it with. Stay safe! :)")


def display_ascii_art():
    ascii_art = """
      ____             _       _   ____  _     _      _     _ 
     / ___|  ___   ___(_) __ _| | / ___|| |__ (_) ___| | __| |
     \___ \ / _ \ / __| |/ _` | | \___ \| '_ \| |/ _ \ |/ _` |
      ___) | (_) | (__| | (_| | |  ___) | | | | |  __/ | (_| |
     |____/ \___/ \___|_|\__,_|_| |____/|_| |_|_|\___|_|\__,_|
    """
    print(ascii_art)

# Usage example
if __name__ == "__main__":
    display_ascii_art()
    social_shield = SocialShield()
    chosen_platform = social_shield.choose_platform()

    if chosen_platform == 'Instagram':
        # Instagram Functionality
        # Prompt for Instagram credentials
        ig_username = input("Enter your Instagram username: ")
        ig_password = input("Enter your Instagram password: ")

        # Perform login
        social_shield.login(ig_username, ig_password)

        # Enter the usernames of the Instagram profiles to be analyzed
        profile_name = input("Enter your Instagram profile name to analyze: ")
        social_shield.analyze_profile(profile_name)
        social_shield.process_directory_for_tagged_users(os.path.join(os.getcwd(), profile_name))

    elif chosen_platform == 'Snapchat':
        snapchat_username = input("Enter your Snapchat username to analyze: ")
        social_shield.analyze_snapchat(snapchat_username)
