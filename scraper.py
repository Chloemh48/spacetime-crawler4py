import re
# TODO import tokenizer
from nltk.corpus import stopwords
from bs4 import BeautifulSoup

from urllib.parse import urlparse
from spacetime import Node


all_urls = []

def scraper(url, resp):
    links = extract_next_links(url, resp)
    all_urls.append(url)
    return [link for link in links if is_valid(link)]

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
    if resp.status != 200:
        return []
    
    
    if resp.raw_response is None or resp.raw_response.content is None or url is None:
        return []
    

    content = resp.raw_response.content.decode("utf-8", errors="ignore")

    if CheckLargeFile():
        return []
    
    if CheckLowInformation(content):
        return []
    
    # Decode the content of the response
    


    # Extract all links using a regular expression to find href attributes
    extracted_links = re.findall(r'href=[\'"]?([^\'" >]+)', content)

    # Filter out the links that are not valid
    valid_links = []
    for link in extracted_links:
        if is_valid(link):
            valid_links.append(link)
        
    return valid_links




def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if parsed.netloc == "today.uci.edu" and parsed.path.startswith("/department/information_computer_sciences/"):
            return True
        
         # Only allow URLs within the ics.uci.edu domain
        if not re.match(r".*\.(ics\.uci\.edu|cs\.uci\.edu|informatics\.uci\.edu|stat\.uci\.edu)", parsed.netloc):
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
def CheckLowInformation(content):
    # Threshold of 300 words?
    if len(content) < 300:
        return True
    return False


# Might need to update?
def CheckLargeFile(content):
    threshold = 10 * 1024 * 1024 # Threshold of 10MB ? 
    content_size = int(content.headers.get("Content-length",0))
    if content_size > threshold:
        return True
    return False




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
