"""
  ____             _       _   ____  _     _      _     _ 
 / ___|  ___   ___(_) __ _| | / ___|| |__ (_) ___| | __| |
 \___ \ / _ \ / __| |/ _` | | \___ \| '_ \| |/ _ \ |/ _` |
  ___) | (_) | (__| | (_| | |  ___) | | | | |  __/ | (_| |
 |____/ \___/ \___|_|\__,_|_| |____/|_| |_|_|\___|_|\__,_|
                                                          

Social Media Vulnerability Scanner

Justin Balroop
"""

# Add 'help' command to list all available commands, followed by a description of each command
# 

import os
import sys
import time
import instaloader
from pii_codex import PiiCodex
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

class SocialShield:
    def __init__(self):
        self.loader = instaloader.Instaloader()
        self.pii_codex = PiiCodex()

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

        # Check for geotagged posts
        for post in profile.get_posts():
            if post.location:
                report["geotagged_posts"].append({
                    "post_url": post.url,
                    "location": post.location.name
                })

        # Detect PII using PII Codex
        pii_results = self.pii_codex.find_pii(text=profile.biography)
        for pii in pii_results:
            report["detected_pii"].append({
                "type": pii['type'],
                "value": pii['match']
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
    usernames = ["exampleuser1", "exampleuser2"]  # Replace with target usernames
    reports = social_shield.scan_profiles(usernames)

    for report in reports:
        print(report)
