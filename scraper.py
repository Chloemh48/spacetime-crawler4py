import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment
from collections import Counter
from spacetime import Node
import chardet
import time 

last_save_time = time.time() 
save_interval = 5 

# Global variables
# tokens = {}
scraped_urls = set() # URLs that have been scraped
seen_urls = set()
unique_urls = {}
blacklisted_urls = set()
max_words = ["", 0] # URL with the most words
word_frequencies = Counter()
subdomains = {}


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

def scraper(url, resp):
    try:
        links = extract_next_links(url, resp)
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
    global max_words, word_frequencies, unique_urls, subdomains, last_save_time
    if resp.status != 200:
        blacklisted_urls.add(url)
        return []
    if resp.raw_response is None or resp.raw_response.content is None:
        return []
    
    if CheckLargeFile(resp):
        blacklisted_urls.add(url)
        return []
    

    content = resp.raw_response.content
    detected = chardet.detect(content)
    encoding = detected['encoding'] if detected['encoding'] else 'utf-8'
    decoded_content = content.decode(encoding, errors='ignore')
    soup = BeautifulSoup(decoded_content, "lxml")  # Use decoded_content here
    
    if CheckLowInformation(soup):
        return []
    
    # Clean the soup: remove comments and unwanted tags
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    for tag in soup.find_all(['script', 'style']):
        tag.extract()
    
    # Extract and normalize text, update max words if applicable
    page_text = soup.get_text()
    words = extract_words(page_text)
    word_count = len(words)
    word_frequencies.update(words)

    # # Update tokens with the words for this specific page
    # tokens[url] = words  # Store the list of words for the current page URL


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
    link_count = 0 
    for anchor in soup.find_all('a', href=True):
        href = urljoin(url, anchor['href'].split('#')[0])
        link_count += 1  # Increment link counter
    
    # Check for potential crawl loops
        if href in seen_urls:
            seen_urls[href] += 1  
            if seen_urls[href] > 5:  # Adjust threshold as needed
                blacklisted_urls.add(href)
                continue  
        else:
            seen_urls[href] = 1  
  
        if link_count > 100:  
            blacklisted_urls.add(url) 
            return []  

        if is_valid(href) and href not in seen_urls:
            links.add(href)

   
    current_time = time.time()
    print("huuuuuu")
    if current_time - last_save_time >= save_interval:
        print("HEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
        save_report() 
        last_save_time = current_time 
    
    return list(links)

def extract_words(text):
    """Extract words from text, removing special characters."""
    words = re.findall(r'\b\w+\b', text.lower())
    return [word for word in words if word not in STOP_WORDS]



def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    global blacklisted_urls
    try:
        parsed = urlparse(url)
        if parsed.scheme not in (["http", "https"]):
            return False
        
      
        allowed_domains = {
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        }
        

        if parsed.netloc == "today.uci.edu":
           return parsed.path.startswith("/department/information_computer_sciences/")
        
         # Check if domain matches any allowed domain
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False
        if url in blacklisted_urls:
            return False
        
        if any(pattern in url for pattern in ["?share=", "pdf", "redirect", "#comment", "#respond", "#comments"]):
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


def CheckLowInformation(content: BeautifulSoup) -> bool:
    return len(content.get_text().split()) < 300


def CheckLargeFile(resp) -> bool:
    threshold = 10 * 1024 * 1024  # 10 MB
    # Attempt to get 'Content-Length' or fallback to measuring length of raw content
    content_size = int(resp.headers.get("Content-Length", len(resp.raw_response.content)) if hasattr(resp, 'headers') else len(resp.raw_response.content))
    return content_size > threshold




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
    for word, count in word_frequencies.most_common(50):
        print(f"{word}: {count}")
    print("\nSubdomains found:")
    for domain, count in sorted(subdomains.items()):
        print(f"{domain}: {count} pages")

