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
import sys
import time
import json
import argparse
import subprocess
import instaloader
from presidio_analyzer import AnalyzerEngine
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

# Only Instagram functionality as of right now
class SocialShield:
    def __init__(self):
        self.loader = instaloader.Instaloader()
        self.analyzer = AnalyzerEngine()

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

    def extract_exif(self, file_path):
        try:
            image = Image.open(file_path)
            gps_coords = {}

            if image._getexif() is None:
                return None

            for tag, value in image._getexif().items():
                tag_name = TAGS.get(tag)
                if tag_name == "GPSInfo":
                    for key, val in value.items():
                        if GPSTAGS.get(key) == "GPSLatitude":
                            gps_coords["lat"] = val
                        elif GPSTAGS.get(key) == "GPSLongitude":
                            gps_coords["lon"] = val
                        elif GPSTAGS.get(key) == "GPSLatitudeRef":
                            gps_coords["lat_ref"] = val
                        elif GPSTAGS.get(key) == "GPSLongitudeRef":
                            gps_coords["lon_ref"] = val
            return gps_coords

        except IOError:
            return None

    def analyze_profile(self, username):
        profile = instaloader.Profile.from_username(self.loader.context, username)

        # Initializing data storage
        report = {
            "username": username,
            "geotagged_posts": [],
            "detected_pii": []
        }

        try:
            for post in profile.get_posts():
                # Download the image associated with the post
                self.loader.download_post(post, target=profile.username)

                # Check if the post has a location tag
                if post.location:
                    report["geotagged_posts"].append({
                        "post_url": post.url,
                        "location": post.location.name
                    })

                # Analyze images for EXIF data
                post_dir = os.path.join(os.getcwd(), profile.username, post.shortcode)
                if os.path.isdir(post_dir):
                    for file in os.listdir(post_dir):
                        file_path = os.path.join(post_dir, file)
                        exif_data = self.extract_exif(file_path)
                        if exif_data:
                            report["geotagged_posts"].append({
                                "post_url": file_path,
                                "location": self.gmaps(exif_data)
                            })

            # Detect PII using Presidio Analyzer
            analysis_results = self.analyzer.analyze(text=profile.biography, language='en')
            for result in analysis_results:
                report["detected_pii"].append({
                    "type": result.entity_type,
                    "value": profile.biography[result.start:result.end]
                })

            # Download and analyze images for EXIF data
            self.loader.download_profile(username, profile_pic_only=False)
            profile_dir = os.path.join(os.getcwd(), username)
            for file in os.listdir(profile_dir):
                file_path = os.path.join(profile_dir, file)
                exif_data = self.extract_exif(file_path)
                if exif_data:
                    report["geotagged_posts"].append({
                        "post_url": file_path,
                        "location": self.gmaps(exif_data)
                    })

        except Exception as e:
            print(f"Error analyzing profile {username}: {e}")
            return {"username": username, "geotagged_posts": [], "detected_pii": []} 
            # return an empty report for this profile
        
        return report

    def print_post_details(json_file_path):
        try:
            # Open and load the JSON file
            with open(json_file_path, 'r') as file:
                post_data = json.load(file)
            
            # Extract the desired information
            full_name = post_data.get('node', {}).get('owner', {}).get('full_name', 'N/A')
            username = post_data.get('node', {}).get('owner', {}).get('username', 'N/A')
            is_private = post_data.get('node', {}).get('owner', {}).get('is_private', 'N/A')
            
            # Print the information
            print("Post Details:")
            print(f"Full Name: {full_name}")
            print(f"Username: {username}")
            print(f"Is Private: {is_private}")
        except FileNotFoundError:
            print("File not found. Please check the file path.")
        except json.JSONDecodeError:
            print("Error decoding JSON. Please check the file content.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

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
        with lzma.open(xz_file_path) as file:
            file_content = file.read()
            with open(output_path, 'wb') as output_file:
                output_file.write(file_content)

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

    # # Create the parser
    # parser = argparse.ArgumentParser(description="Extract and print information from an Instagram post JSON file.")
    
    # # Add an argument for specifying the JSON file path
    # parser.add_argument('-f', '--file', type=str, required=True, help="Path to the Instagram post JSON file.")
    
    # # Parse the command-line arguments
    # args = parser.parse_args()
    
    # # Call the function to print post details using the provided JSON file path
    # print_post_details(args.file)

    if chosen_platform == 'Instagram':
        # Instagram Functionality
        # Prompt for Instagram credentials
        ig_username = input("Enter your Instagram username: ")
        ig_password = input("Enter your Instagram password: ")

        # Perform login
        social_shield.login(ig_username, ig_password)

        # Enter the usernames of the Instagram profiles to be analyzed
        target_usernames = input("Enter the usernames of the Instagram profiles to analyze (separated by a comma): ")
        usernames_list = target_usernames.split(',')

        # Scan profiles and generate reports
        reports = social_shield.scan_profiles(usernames_list)

        # Create the parser
        parser = argparse.ArgumentParser(description="Extract information from an Instagram post JSON file, optionally extracting it from an .xz archive first.")
        
        # Add an argument for the JSON file path
        parser.add_argument('-f', '--file', type=str, help="Path to the Instagram post JSON file.")
        
        # Add an argument for the .xz file path
        parser.add_argument('-x', '--extract', type=str, help="Path to the .xz file to extract.")

        # Parse the command-line arguments
        args = parser.parse_args()
        
        if args.extract:
            # Extract the .xz file to the same directory with a .json extension
            output_path = os.path.splitext(args.extract)[0] + ".json"
            extract_xz_file(args.extract, output_path)
            print(f"Extracted to {output_path}")
            
            # Update the JSON file path argument to use the extracted file
            args.file = output_path

        if args.file:
            # Call the function to print post details using the provided JSON file path
            print_post_details(args.file)
        else:
            print("Please specify a file to process with -f or an .xz file to extract with -x.")

        # Display the analysis reports
        for report in reports:
            print("Analysis Report for:", report['username'])

            # Display geotagged posts
            print("\nGeotagged Posts:")
            for post in report['geotagged_posts']:
                print(" - Post URL:", post['post_url'])
                if 'location' in post:
                    print(" - Location:", post['location'])

            # Display detected PII
            print("\nDetected PII in Biography:")
            for pii in report['detected_pii']:
                print(" - Type:", pii['type'])
                print(" - Value:", pii['value'])
            print("\n")

            print(report)
        pass
    elif chosen_platform == 'Snapchat':
        snapchat_username = input("Enter your Snapchat username to analyze: ")
        social_shield.analyze_snapchat(snapchat_username)
