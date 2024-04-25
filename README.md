# Social Shield
Social Shield is a Social Media Vulnerability Scanner that can analyze profiles from Instagram and Snapchat, revealing potential privacy risks and providing tailored privacy tips.

## Features
- Login functionality for Instagram with support for two-factor authentication.
- Extract and analyze EXIF data from downloaded media.
- Detailed privacy tips for both Instagram and Snapchat users.
- Ability to scan multiple profiles and summarize potential vulnerabilities.

## Getting Started

### Prerequisites
Before running Social Shield, you need to install the required Python libraries and external tools.

#### Install Python Libraries
Run the following command in your terminal to install the necessary Python libraries:

```bash
pip install instaloader lzma subprocess
```

#### External Tools
You'll also need to install the following tools:

ExifTool: A platform-independent Perl library plus a command-line application for reading, writing, and editing meta information in a wide variety of files.
SnapIntel: A tool specifically designed for extracting information from Snapchat.

##### For ExifTool, installation can vary based on your operating system:

###### For macOS:
```bash
brew install exiftool
```

###### For Ubuntu:
```bash
sudo apt-get install libimage-exiftool-perl
```

###### For Windows:
Download and install from ExifTool's official website: https://exiftool.org/

For SnapIntel, clone the repository from GitHub:
```bash
git clone https://github.com/Kr0wZ/SnapIntel
```

### Running Social Shield
To run the program, navigate to the directory containing socialshield.py and execute the following command:
```bash
python3 socialshield.py
```
