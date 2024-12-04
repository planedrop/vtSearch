# Import modules
import os
import csv
import random
import requests
import json

# Generate random 3 digit number for filename
random_num = str(random.randint(100,999))

# Get API key from user input
api_key = input("Enter your VirusTotal API key: ")

# Get folder path from user input
folder_path = input("Enter folder path: ")

# Output CSV filename
output_file = 'vt_results_' + random_num + '.csv'

# Open CSV file for writing
with open(output_file, 'w', newline='') as csvfile:

  # Create CSV writer
  writer = csv.writer(csvfile)

  # Write header row
  writer.writerow(['Filename', 'Scan URL'])

  # Walk through the directory tree
  for root, dirs, files in os.walk(folder_path):
    for filename in files:

      # Construct full file path
      file_path = os.path.join(root, filename)

      try:
        # Open file in binary mode
        with open(file_path, 'rb') as f:

          # Construct payload with file contents
          files = {'file': (filename, f)}

          # Make API request
          response = requests.post(
            'https://www.virustotal.com/vtapi/v2/file/scan',
            files=files,
            headers={'API-Key': api_key}  # Note: VirusTotal uses x-apikey instead of API-Key in the header
          )

          # Check response status code
          if response.status_code == 200:

            # Extract scan URL
            url = response.json()['permalink']

            # Write row to CSV
            writer.writerow([filename, url])

          else:
            print(f'Error uploading {file_path}')

      except Exception as e:
        print(f'An error occurred processing {file_path}: {e}')

# Print output filename
print(f'Results written to {output_file}')
