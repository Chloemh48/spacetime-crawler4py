import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, u
from bs4 import BeautifulSoup, Comment
from collections import Counter
from spacetime import Node
import chardet
import time


SAVE_INTERVAL = 60  # Save every 5 minutes
last_save_time = time.time()  # Track the last save time




last_save_time = time.time()  # Initialize the last save time
save_interval = 5  # Set the interval (in seconds) for saving the report

# Global variables
# tokens = {}
scraped_urls = set() # URLs that have been scraped
seen_urls = {}
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
    global max_words, unique_urls, subdomains,  last_save_time
    # Rest of the function remains the same
    if resp.status != 200:
        print(f"Blacklisting URL: {url} due to status: {resp.status}")
        blacklisted_urls.add(url)
        return []
    if resp.raw_response is None or resp.raw_response.content is None:
        print(f"No content for URL: {url}")
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
    
    for tag in soup(['footer', 'header', 'meta', 'nav']):
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
    scraped_urls.add(url)
    if '.uci.edu' in parsed_url.netloc:
        subdomain = parsed_url.netloc
        subdomains[subdomain] = subdomains.get(subdomain, 0) + 1
    
     # Extract links
    # Extract links
    links = set()
    link_count = 0  # Counter for the number of links found on the page
    for anchor in soup.find_all('a', href=True):
        href = urljoin(url, anchor['href'].split('#')[0])
        normalized_href = normalize_url(href)
        print("HEY" + " " + normalized_href)

        # Prevent cycles
        if normalized_href == base_url or normalized_href in seen_urls and seen_urls[normalized_href] > 5:
            continue

        # Update seen URLs
        seen_urls[normalized_href] = seen_urls.get(normalized_href, 0) + 1

        if is_valid(normalized_href) and normalized_href not in blacklisted_urls:
            links.add(normalized_href)

    # Check if it's time to save the report
    current_time = time.time()
    if current_time - last_save_time >= save_interval:
        save_report()  # Call save_report function
        last_save_time = current_time  # Update the last save time
    
    return list(links)

def extract_words(text):
    """Extract words from text, removing special characters."""
    tokens = re.findall(r'\b[a-zA-Z0-9]{3,}\b', text)
    # Normalize tokens to lowercase and filter out stop words
    return [word.lower() for word in tokens if word.lower() not in STOP_WORDS]



def is_valid(url):
    """Decides whether to crawl the given URL or not."""
    global blacklisted_urls
    
    try:
        # Parse the URL
        parsed = urlparse(url)
        
        # Check if the scheme is valid
        if parsed.scheme not in ("http", "https"):
            return False

        # Define allowed domains
        allowed_domains = {
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        }

        # Define unwanted patterns in the URL
        unwanted_patterns = [
            "filter", "tribe-bar-date=", "/events/", "outlook-ical=", "ical=1", 
            "/month/", "/list/", "eventDisplay=past", "?share=", "pdf", 
            "redirect", "#comment", "#respond", "#comments", 
            "seminar_id=", "archive_year=", "/department-seminars/", "/seminar-series/",
            "year", "month", "day", "date", "week", "calendar", "login", "html"
            "archive", "history", "past", "previous",
            r"\b\d{4}\b"  # Matches four-digit years
        ]

        # Special case for today.uci.edu domain
        if parsed.netloc == "today.uci.edu":
            return parsed.path.startswith("/department/information_computer_sciences/")

        # Check if the domain matches any allowed domain
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False
        
        # Check if the URL is blacklisted
        if url in blacklisted_urls:
            return False
        
        # Check for unwanted patterns in the path or query
        for pattern in unwanted_patterns:
            if re.search(pattern, url):
                return False
        
        # Check for date format in URL paths (e.g., YYYY-MM-DD)
        date_pattern = r"/\d{4}-\d{2}-\d{2}/"
        if re.search(date_pattern, parsed.path):
            return False
        
        # Check if the URL is pointing to static files
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$", 
            parsed.path.lower()):
            return False
        
        # If all checks pass, return True
        return True

    except TypeError:
        print("TypeError for ", url)
        return False  # Return False for invalid URLs


def CheckLowInformation(content: BeautifulSoup) -> bool:
    return len(content.get_text().split()) < 300


def CheckLargeFile(resp) -> bool:
    threshold = 10 * 1024 * 1024  # 10 MB
    # Attempt to get 'Content-Length' or fallback to measuring length of raw content
    content_size = int(resp.headers.get("Content-Length", len(resp.raw_response.content)) if hasattr(resp, 'headers') else len(resp.raw_response.content))
    return content_size > threshold


def CheckLowInformation(content: BeautifulSoup) -> bool:
    return len(content.get_text().split()) < 300













def save_report(filename="crawler_report.txt"):
    """Save crawling statistics to a file."""
    try:
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

#path to itself return
#no links
#links with dates
#
from urllib.parse import urlparse, urlunparse

def normalize_url(url):
    # Parse the URL
    parsed = urlparse(url)
    
    # Rebuild the URL without query parameters and fragment
    normalized_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        '',           # Empty query string
        ''            # Empty fragment
    ))
    
    return normalized_url.lower()
 


def tokenize(text):
    for line in text:
        token = ""
        for character in text:
            if(character.isalpha() or character.isnumeric()):
                token += character
            else:
                #If there exist a token insert it in the token list
                #Reset the token to empty after you insert to reset the process
                if token:
                    yield(token)
                token = ""
        #Adds last token if there exists
        #Accounts for edge case if there is a remaning token and the for loop ended
        if token:
            yield(token)


#Time complexity is O(n) since it does a for loop n times (amount of tokens) and it inserts/looks
#up in the dictionary which is O(1)
#Last for loop is O(n) reverting dictionary back into the list format
#returns list of [word, frequency]
def computeWordFrequencies(token_list):
    
    word_frequency_list_dict = {}
    freq_list = []
    
    for token in token_list:
         
        #lowercase the token to "normalize it"
        lower_token = token.lower()

        if lower_token in word_frequency_list_dict:
            word_frequency_list_dict[lower_token] += 1
            
        else:
            word_frequency_list_dict[lower_token] = 1
    
    for token, frequency in word_frequency_list_dict.items():
        freq_list.append([token, frequency])

    return freq_list
         
            

#Looked at pseudocode section from source url https://www.tutorialspoint.com/data_structures_algorithms/insertion_sort_alg
# Did not look at python code section 
#Sorting function is O(n^2) at worst case and best case O(n) as inner while loop will never be called if sorted
def customInsertionSort(list_to_be_sorted):
    len_of_arr = len(list_to_be_sorted)

    for j in range(1, len_of_arr):
        key = list_to_be_sorted[j]
        i = j -1
        while(i >= 0 and list_to_be_sorted[i][1] < key[1]):
            list_to_be_sorted[i + 1] = list_to_be_sorted[i]
            i -= 1
        list_to_be_sorted[i + 1] = key

    return list_to_be_sorted

#Time complexity is O(n(n^2)) worst case since youll have to sort it using insertion sort
#Best case is O(n) if its already sorted and you just print + n times
def printFrequencies(Frequencies):
    #sort function
    sorted_list = customInsertionSort(Frequencies)
    for sublist in sorted_list:
        print(sublist[0] + " - " + str(sublist[1]))

