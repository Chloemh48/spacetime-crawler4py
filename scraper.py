import re
# TODO import tokenizer
from nltk.corpus import stopwords
from bs4 import BeautifulSoup, Comment
from collections import Counter

from urllib.parse import urlparse, urljoin
from spacetime import Node
import time


all_urls = []
total_words = []
tokens = {}
scraped_urls = set()
seen_urls = set()
unique_urls = {}
blacklisted_urls = set()
max_words = {"",0}
word_frequencies = Counter()
subdomains = {}
previous_loc = ""
start_time = time.time()


time_limit = 1800 # Time limit of 30 minutes to scrap similar subdomain names

STOP_WORDS = {'ours', 'you', 'because', 'of', 'whom', 'my', 'them', 'into', 'under', 'on', "couldn't", 'yours', 'few', 's', 
              'was', 'most', 'aren', 'so', 'our', 'shouldn', 'had', "she's", 'haven', "you've", 'itself', 'if', 'about', 
              'only', "that'll", 'very', 'won', 'in', 'and', 'they', 'are', "you'd", 'down', 'nor', "don't", 'the', 'than', 
              'ain', 'y', 'below', 're', 'how', 'once', 'while', 'she', 'against', "should've", 'be', 'don', 'ourselves', 'off',
              'hers', 'its', 'both', 'm', 'who', "doesn't", 'his', "mightn't", 'then', 'it', 'those', "weren't", 'now', 'd', 
              'he', 'through', "haven't", 'me', 'have', 'each', 'himself', 'where', 'other', 'all', 'after', 'at', 'these', 'until',
              "aren't", "shouldn't", 'your', 'why', 'couldn', 'him', 'does', "isn't", 'just', 'shan', 'but', 'll', 'am', 'is', 
              "didn't", 'which', 'wasn', 'should', 'her', "hasn't", 'o', "hadn't", "shan't", 'herself', 'doesn', "it's", 'myself',
              'here', 'there', 'by', 'hasn', 'theirs', 'has', 'out', 'weren', 'yourself', "won't", 'can', 'up', 'having', 'doing', 
              'being', 'an', 'with', 'mightn', 'to', 'isn', 'themselves', 'not', 'will', 'were', 've', 'same', 'this', 'some', 'their', 
              "you're", 'been', 'over', 'when', 'i', 'yourselves', 'before', "wouldn't", 'ma', 'for', 'further', 'a', 'between', 'what',
              'such', 'did', "you'll", "wasn't", 'too', 'any', 'own', 'during', 'above', 'from', 'more', 'we', "mustn't", 'or', 'wouldn',
              'mustn', 'that', 'no', 'didn', 'again', "needn't", 't', 'as', 'needn', 'hadn', 'do'}

def scraper(url, resp):
    try:
        links = extract_next_links(url,resp)
        return [link for link in links if is_valid(link)]
    except Exception as e:
        print(f"Error in scraper for URL {url}: {e}")
        return []

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    # Check if the response is valid
    if resp.status != 200 or resp.raw_response is None or resp.raw_response.content is None or url is None: 
        return []
    
    soup = BeautifulSoup(resp.raw_response.content, 'lxml')

    if CheckLargeFile(resp.raw_response):
        return []
    
    if CheckLowInformation(soup):
        return []
    
    
    
    # Cleaning soup
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    for tag in soup.find_all(['script', 'style', 'meta', 'link', 'iframe', 'embed', 
                              'noscript', 'form', 'input', 'button', 'nav', 
                              'footer', 'aside', 'header', 'figure', 'figcaption']):
        tag.extract()
    
    page_text = soup.get_text()
    words = extract_words(page_text)
    word_count = len(words)
    word_frequencies.update(words)

    scraped_urls.add(url)


    base_url = url.split('#')[0]  # Remove fragment
    unique_urls[base_url] = word_count
    
    if word_count > max_words[1]:
        max_words = [url, word_count]
    
      # Update subdomain statistics
    parsed_url = urlparse(url)
    if '.uci.edu' in parsed_url.netloc:
        subdomain = parsed_url.netloc
        subdomains[subdomain] = subdomains.get(subdomain, 0) + 1
    
     # Extract links
    links = set()
    for anchor in soup.find_all('a', href=True):
        href = urljoin(url, anchor['href'].split('#')[0])
        if is_valid(href) and href not in seen_urls:
            links.add(href)
            seen_urls.add(href)
    
    
    return list(links)

def extract_words(text):
    """Extract words from text, removing special characters."""
    words = re.findall(r'\b\w+\b', text.lower())
    return [word for word in words if word not in STOP_WORDS and len(word) > 1]

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.


    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        # Allowed domain names
        allowed_domains = {
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        }
        
        if detect_trap(url, parsed):
            return False

        # If the net location is today.uci.edu then check if the site is from the ICS department
        if parsed.netloc == "today.uci.edu":
           return parsed.path.startswith("/department/information_computer_sciences/")
        
         # Check if domain matches any allowed domain
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False

      
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

# Might need to update?
def CheckLowInformation(content:BeautifulSoup) -> bool:
    # Threshold of 300 words?
    if len(content.get_text().split) < 300:
        return True
    return False


# Might need to update?
def CheckLargeFile(content) -> bool:
    threshold = 10 * 1024 * 1024 # Threshold of 10MB ? 
    content_size = int(content.headers.get("Content-length",0))
    if content_size > threshold:
        return True
    return False

def detect_trap(url, resp) -> bool:
    if url in scraped_urls or url in seen_urls or url in blacklisted_urls:
        return True
    if time.time() - start_time >= 1800: # 30 Minute time limit on using the same subdomain
        if resp.netloc == previous_loc.netloc:
            return True
        else:
            start_time = 0
    return False

    




def save_report(filename="crawler_report.txt"):
    """Save crawling statistics to a file."""
    with open(filename, "w", encoding='utf-8') as f:
        f.write("Web Crawler Report\n")
        f.write("=================\n\n")
        
        f.write(f"1. Number of unique pages: {len(unique_urls)}\n\n")
        
        f.write(f"2. Longest page:\n")
        f.write(f"   URL: {max_words[0]}\n")
        f.write(f"   Word count: {max_words[1]}\n\n")
        
        f.write("3. 50 most common words:\n")
        for word, count in word_frequencies.most_common(50):
            f.write(f"   {word}: {count}\n")
        f.write("\n")
        
        f.write("4. Subdomains and page counts:\n")
        for domain, count in sorted(subdomains.items()):
            f.write(f"   {domain}, {count}\n")

def print_statistics():
    """Print current crawling statistics to the console."""
    print(f"Unique URLs found: {len(unique_urls)}")
    print(f"Longest page: {max_words[0]} with {max_words[1]} words")
    print("\nTop 10 most common words:")
    for word, count in word_frequencies.most_common(10):
        print(f"{word}: {count}")
    print("\nSubdomains found:")
    for domain, count in sorted(subdomains.items()):
        print(f"{domain}: {count} pages")


def calculate_unique_urls(urls):
    unique_set = set()
    for url in urls:
        # Removing fragments
        normalized_url, _ = urldefrag(url)
        unique_set.add(normalized_url)
        unique_list = list(unique_set)

    try:
        with open(json_file_path, "r") as f:
            existing_data = json.load(f)
    except FileNotFoundError:
        existing_data = []
    all_urls = list(set(existing_data + unique_list))

    with open(json_file_path, "w") as f:
        json.dump(all_urls, f, indent=4)
    
    print(f"Saved {len(all_urls)} unique URLs to {json_file_path}")
