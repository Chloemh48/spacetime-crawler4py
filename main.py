import sys
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup, Comment
import chardet
import re

STOP_WORDS = {
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and',
    'any', 'are', "aren't", 'as', 'at', 'be', 'because', 'been', 'before',
    'being', 'below', 'between', 'both', 'but', 'by', "can't", 'cannot', 'could',
    "couldn't", 'did', "didn't", 'do', 'does', "doesn't", 'doing', "don't",
    'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', "hadn't",
    'has', "hasn't", 'have', "haven't", 'having', 'he', "he'd", "he'll", "he's",
    'her', 'here', "here's", 'hers', 'herself', 'him', 'himself', 'his', 'how',
    "how's", 'i', "i'd", "i'll", "i'm", "i've", 'if', 'in', 'into', 'is',
    "isn't", 'it', "it's", 'its', 'itself', "let's", 'me', 'more', 'most',
    "mustn't", 'my', 'myself', 'no', 'nor', 'not', 'of', 'off', 'on', 'once',
    'only', 'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out', 'over',
    'own', 'same', "shan't", 'she', "she'd", "she'll", "she's", 'should',
    "shouldn't", 'so', 'some', 'such', 'than', 'that', "that's", 'the', 'their',
    'theirs', 'them', 'themselves', 'then', 'there', "there's", 'these', 'they',
    "they'd", "they'll", "they're", "they've", 'this', 'those', 'through', 'to',
    'too', 'under', 'until', 'up', 'very', 'was', "wasn't", 'we', "we'd",
    "we'll", "we're", "we've", 'were', "weren't", 'what', "what's", 'when',
    "when's", 'where', "where's", 'which', 'while', 'who', "who's", 'whom',
    'why', "why's", 'with', "won't", 'would', "wouldn't", 'you', "you'd",
    "you'll", "you're", "you've", 'your', 'yours', 'yourself', 'yourselves'
}

# Dictionary to track the count of each normalized URL
seen_urls = {}


def rep_segment(parsed_url, threshold=3):
    path_segments = parsed_url.path.split('/')
    segment_counts = {}
    
    for segment in path_segments:
        if not segment:
            continue
        
        if segment in segment_counts:
            segment_counts[segment] += 1
        else:
            segment_counts[segment] = 1
        
        if segment_counts[segment] >= threshold:
            return True
    
    return False





def normalize_url(url):
    # Parse the URL and remove only the query parameters
    parsed_url = urlparse(url)
    # Rebuild the URL without the query component
    normalized_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, "", parsed_url.fragment))
    return normalized_url


def extract_words(text):
    """Extract words from text, removing special characters."""
    tokens = re.findall(r'\b[a-zA-Z0-9]{3,}\b', text)
    # Normalize tokens to lowercase and filter out stop words
    return [word.lower() for word in tokens if word.lower() not in STOP_WORDS]

def CheckLowInformation(content: BeautifulSoup) -> bool:
    return len(content.get_text().split()) < 300

def links(html_path):


    with open(html_path, "rb") as file:
        content = file.read()
        detected = chardet.detect(content)
        encoding = detected['encoding'] if detected['encoding'] else 'utf-8'
        decoded_content = content.decode(encoding, errors='ignore')

# Step 2: Parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(decoded_content, "lxml")

    if CheckLowInformation(soup):
        print("Is low info")
    # Clean the soup: remove comments and unwanted tags
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    for tag in soup.find_all(['script', 'style']):
        tag.extract()
    
    for tag in soup(['footer', 'header', 'meta', 'nav']):
        tag.extract()

    # Extract page text and split into words
    page_text = soup.get_text()
    words = extract_words(page_text)
    word_count = len(words)  # Total word count

    # Print word list and word count
    print("Words in page:", words)
    print("Total word count:", word_count)

    # Check for login-related keywords
    keywords = ["login", "sign in", "signup", "password", "calendar"]
    for keyword in keywords:
        if keyword in page_text.lower():  # Convert to lowercase for case-insensitive search
            print(f"The keyword '{keyword}' is present in the page.")

def is_valid(url):
    # Parse the URL
    parsed_url = urlparse(url)

    if rep_segment(parsed_url):
        return url
    # Check if there are any query parameters
    if parsed_url.query:
        return url  # Return the original URL if there are query parameters


def process_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
        for line in infile:
            line = line.strip()
            # Extract substring up to the first whitespace
            url_candidate = line.split()[0] if line else ""

            # Check if the URL is invalid based on threshold
            result = is_valid(url_candidate)
            if result:  # If result is not False, it means the URL is either invalid or hit the threshold
                outfile.write(f"{result}\n")  # Write the URL to the output file
                print(f"URL '{result}' has been processed and written to the output file.")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        print("Usage: python main.py <input_file> <output_file>")
        sys.exit(1)

    #input_file = sys.argv[1]
    #output_file = sys.argv[2]


    links("events.html")
    #process_file(input_file, output_file)
