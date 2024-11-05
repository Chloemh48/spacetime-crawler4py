
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment
from collections import Counter
from spacetime import Node
import chardet
import time

import nltk
from nltk.corpus import stopwords


SAVE_INTERVAL = 60  # Save every 1 minutes
last_save_time = time.time()  # Track the last save time



# Downloaded the stopwords package
nltk.download('stopwords')
nltk.download('punkt')

# Global variables
# tokens = {}
scraped_urls = set() # URLs that have been scraped
seen_urls = set()
unique_urls = {}
blacklisted_urls = set()
max_words = ["", 0] # URL with the most words
word_frequencies = Counter()
subdomains = {}
url_hash = {}
checksum_dict = {}


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
    global max_words, word_frequencies, unique_urls, subdomains,  last_save_time

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

    # # Remove structural or non-essential tags: <footer>, <header>, <meta>, <nav>
    # for tag in soup(['footer', 'header', 'meta', 'nav']):
    #     tag.extract()
    
 
    # Extract visible text
    # page_text = soup.get_text()
    
    page_text_for_simhash = soup.get_text().split()

    checksum = simple_checksum(page_text_for_simhash)

    if checksum in checksum_dict:
        return []
    else:
        checksum_dict[checksum] = url

    is_near_duplicate = simhash(page_text_for_simhash, url_hash)
    
    if is_near_duplicate:
        url_hash[url] = is_near_duplicate
    
    else:
        return []
        
    page_text = soup.get_text(separator=" ")
    words = extract_words(page_text)
    word_count = len(words)
    word_frequencies.update(words)


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

    current_time = time.time()
    if current_time - last_save_time >= SAVE_INTERVAL:
        save_report()
        last_save_time = current_time  # Update the last save time

    
    
    return list(links)



def extract_words(text):
    stop_words = set(stopwords.words('english'))
    stop_words.update([
        "january", "february", "march", "april", "may", "june", 
        "july", "august", "september", "october", "november", "december",
        "markellekelly", "week", "day"
    ])
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    # Only include words that are alphabetic, have a length >= 3, and are not in STOP_WORDS
    non_stop_words = [
        word for word in words if word.isalpha() and len(word) >= 3 and word not in stop_words
    ]

    return non_stop_words


def is_valid(url):
    # Decide whether to crawl this url or not.
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    global blacklisted_urls
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        
        if parsed.query:
            return False	
	
        if rep_segment(parsed):
            return False
        # filter unwanted urls to avoid traps
    
        unwanted_patterns = [
        "filter", "tribe-bar-date=", "/events/", "outlook-ical=", "ical=1", 
        "/month/", "/list/", "/events/2", "eventDisplay=past", "?share=", "pdf", 
        "redirect", "#comment", "#respond", "#comments", 
        "seminar_id=", "archive_year=", "/department-seminars/", "/seminar-series/",
        "year", "month", "day", "date", "week", "calendar", 
        "archive", "history", "past", "previous", "footer", "header", "meta", "nav"
    ]



      # urls we want to crawl
        allowed_domains = {
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        }
        

        if parsed.netloc == "today.uci.edu":
           return parsed.path.startswith("/department/information_computer_sciences/")
        
         # Check if domain matches any allowed domain
        if not any(parsed.netloc == domain or parsed.netloc.endswith('.' + domain) for domain in allowed_domains):
            return False
        if url in blacklisted_urls:
            return False
        
        # Filter out URLs with unwanted patterns
        if any(pattern in url for pattern in unwanted_patterns):
            return False
      
        return not re.match(
            r".*.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|war|apk|sql|img|ppsx|ps"
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



def simple_checksum(page_text):

    checksum = 0

    full_text = ''.join(page_text)

    for char in full_text:
        ascii_value = ord(char)
        checksum = (checksum + ascii_value) % 1000000007
    
    return checksum

def generate_trigram(list_of_words, max_count = 1000):

    trigrams = set()
    
    count = 0
    for i in range(len(list_of_words)-2):
        trigram = (list_of_words[i], list_of_words[i+1], list_of_words[i+2])
        
        
        sum = 0
        for word in trigram:
            for char in word:
                sum += ord(char)
        
        if sum % 4 == 0:
            if count >= max_count:
                break
            trigrams.add(trigram)
        count += 1
    
    return trigrams



def check_similarity(curr_hash, stored_hash):
    
    intersection = curr_hash.intersection(stored_hash)
    union = curr_hash.union(stored_hash)

    if not union:  # Avoid division by zero
        return 0.0

    # Calculate similarity
    similarity = len(intersection) / len(union)
    
    return similarity

def is_near_duplicates(curr_hash_set, url_hashes):

    threshold = .85
    for url, fingerprints in url_hashes.items():
        similarity = check_similarity(curr_hash_set, fingerprints)

        if similarity >= threshold:
            return True
        
    
    return False 


def simhash(words, url_hashes):


    selected_trigrams = generate_trigram(words)

    if not url_hashes:
        return selected_trigrams

    if is_near_duplicates(selected_trigrams, url_hashes):
        return False

    return selected_trigrams

def rep_segment(parsed_url):
    path_segments = parsed_url.path.split('/')
    segment_counts = {}
    
    for segment in path_segments:
        if not segment:
            continue
        
        if segment in segment_counts:
            segment_counts[segment] += 1
        else:
            segment_counts[segment] = 1
        
        if segment_counts[segment] >= 3:
            return True
    
    return False

def save_report(filename="Report.txt"):
    """Save crawling statistics to a file."""
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write("Web Crawler Report\n")
            f.write("===============================================\n\n")
            
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

            print("Report saved successfully.")
    except IOError as e:
        print(f"Failed to save report due to an IOError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

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








