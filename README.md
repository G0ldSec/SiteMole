# SiteMole
SiteMole is a lightweight Python-based reconnaissance tool built to make web pentesting smoother. It helps you quickly extract valuable insights from target websites. Including comments, links, images, headers, and SRI usage.

## Features

- **Comment Extractor:** Extracts HTML comments from the target webpage.

- **Subresource Integrity (SRI) Checker:** Checks if external JavaScript files use integrity attributes.

- **Link Extractor:** Collects all links found on the page.

- **Image Scraper:** Gathers all image URLs (JPG, PNG, GIF, SVG) from the target.

- **HTTP Header Analyzer:** Retrieves and displays HTTP headers from the server.

- **DNS Lookup:** Resolves the target domain to its IP address.

- **And more are in the pipeline**

## Installation

### Clone the repository:
```
git clone https://github.com/G0ldSec/SiteMole.git
cd SiteMole
```
### Install Dependencies

Ensure you have Python 3 installed. Install the required dependencies using:
```
pip install -r requirements.txt
```

## Usage

Run the script with a target URL and specify a module to execute:
```
python sitemole.py -t https://example.com -m [module]
```
## Available Modules

| **_Module_** |                 **_Description_**                 |
|:------------:|:-------------------------------------------------:|
| comments     | Extracts HTML comments                            |
| sri          | Checks for Subresource Integrity (SRI) usage      |
| links        | Extracts links from the page                      |
| images       | Scrapes image URLs from the page                  |
| headers      | Analyzes HTTP security headers                    |
| all          | Runs all modules and saves results to results.txt |

## Interactive Mode

If no module is specified, an interactive menu allows you to choose a module to run.
```
python sitemole.py -t https://example.com
# or
python sitemole.py
```

## Example Usage

Run the comment extractor:
```
python sitemole.py -t https://example.com -m comments
```
Run all modules and save results:
```
python sitemole.py -t https://example.com -m all
```
Requirements

Ensure you have the following installed:
```
argparse
requests
termcolor
```
These will be automatically installed using pip install -r requirements.txt.

## License

This project is licensed under the MIT License.
## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request with your improvements.

# Disclaimer

**Use this tool for ethical and lawful purposes only. The author takes no responsibility for any misuse or illegal activities carried out using SiteMole.**

