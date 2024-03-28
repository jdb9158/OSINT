"""
  ____             _       _   ____  _     _      _     _ 
 / ___|  ___   ___(_) __ _| | / ___|| |__ (_) ___| | __| |
 \___ \ / _ \ / __| |/ _` | | \___ \| '_ \| |/ _ \ |/ _` |
  ___) | (_) | (__| | (_| | |  ___) | | | | |  __/ | (_| |
 |____/ \___/ \___|_|\__,_|_| |____/|_| |_|_|\___|_|\__,_|
                                                          

Social Media Vulnerability Scanner

"""

# Add 'help' command to list all available commands, followed by a description of each command
# 

import os
import lzma
import json
import argparse
import subprocess
#import exiftool
import instaloader

# Only Instagram functionality as of right now
class SocialShield:
    def __init__(self):
        self.loader = instaloader.Instaloader()

    def choose_platform(self):
        print("Choose a social media platform to scan:")
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

        # Ensure the directory for the profile exists
        profile_dir = os.path.join(username)
        if not os.path.exists(profile_dir):
            os.makedirs(profile_dir)

        for post in profile.get_posts():
            # Download the post
            self.loader.download_post(post, target=username)

            # Construct path to the directory where the post is saved
            post_dir = os.path.join(username, post.shortcode)
            if os.path.isdir(post_dir):
                for file in os.listdir(post_dir):
                    if file.endswith('.xz'):
                        xz_file_path = os.path.join(post_dir, file)
                        json_file_path = xz_file_path[:-3] + ".json"
                        self.extract_xz_file(xz_file_path, json_file_path)
                        self.print_post_details(json_file_path)


    def print_post_details(json_file_path):
        try:
            with open(json_file_path, 'r') as file:
                post_data = json.load(file)
            full_name = post_data.get('full_name', 'N/A')
            username = post_data.get('username', 'N/A')
            print(f"Full Name: {full_name}, Username: {username}")
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

    def extract_xz_file(xz_file_path, output_path):
        try:
            with lzma.open(xz_file_path) as file:
                file_content = file.read()
            with open(output_path, 'wb') as output_file:
                output_file.write(file_content)
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

        try:
            # Save the current working directory
            original_cwd = os.getcwd()

            # Change the working directory to the SnapIntel directory
            os.chdir(snapintel_dir)

            # Construct the command to run SnapIntel
            command_stats = ['python', snapintel_script, '-u', username, '-s']
            # Execute the command
            result = subprocess.run(command_stats, capture_output=True, text=True, check=True)
            
            # Process the result as needed
            if result.returncode == 0:
                print(f"SnapIntel executed successfully for username: {username}")
                print(result.stdout)
            else:
                print(f"SnapIntel encountered an error: {result.stderr}")
                
        except subprocess.CalledProcessError as e:
            print(f"Error running SnapIntel for {username}: {e.stderr}")
        except Exception as e:
            print(f"Error running SnapIntel for {username}: {e}")
        finally:
            # Change back to the original working directory
            os.chdir(original_cwd)


# Usage example
if __name__ == "__main__":
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

    elif chosen_platform == 'Snapchat':
        snapchat_username = input("Enter your Snapchat username to analyze: ")
        social_shield.analyze_snapchat(snapchat_username)
