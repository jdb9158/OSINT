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
import sys
import time
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
        print("1: Instagram\n2: Snapchat\n3: LinkedIn")
        choice = input("Enter your choice (1, 2, or 3): ")
        
        if choice == '1':
            self.loader = instaloader.Instaloader()
            return 'Instagram'
        elif choice == '2':
            # Initialize Snapchat scraping setup here (if available)
            return 'Snapchat'
        elif choice == '3':
            # Initialize LinkedIn scraping setup here (if available)
            return 'LinkedIn'
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
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

    def convert_deci(degree, minutes, seconds, direction):
        """
        Convert GPS coordinates to decimal degrees.

        :param degree: Degree part of the coordinate.
        :param minutes: Minutes part of the coordinate.
        :param seconds: Seconds part of the coordinate.
        :param direction: Direction indicator ('N', 'S', 'E', 'W').
        :return: Decimal degree representation of the coordinate.
        """
        decimal_degrees = degree + minutes / 60 + seconds / 3600
        if direction == "S" or direction == "W":
            decimal_degrees *= -1
        return decimal_degrees
    
    def gmaps(self, gps_records):
        """
        Generate a Google Maps URL from GPS coordinates.

        :param gps_coords: A dictionary containing the GPS coordinates.
                        Expected keys are 'lat', 'lon', 'lat_ref', and 'lon_ref'.
        :return: A string URL for Google Maps.
        """
        dec_lat = convert_deci(float(gps_coords["lat"][0]),  
                            float(gps_coords["lat"][1]), 
                            float(gps_coords["lat"][2]), 
                            gps_coords["lat_ref"])
        dec_lon = convert_deci(float(gps_coords["lon"][0]),  
                            float(gps_coords["lon"][1]), 
                            float(gps_coords["lon"][2]), 
                            gps_coords["lon_ref"])
        return f"https://maps.google.com/?q={dec_lat},{dec_lon}"

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
        target_usernames = input("Enter the usernames of the Instagram profiles to analyze (separated by a comma): ")
        usernames_list = target_usernames.split(',')

        # Scan profiles and generate reports
        reports = social_shield.scan_profiles(usernames_list)

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
