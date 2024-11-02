import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup, Comment
from collections import Counter
from spacetime import Node
import chardet
import time
import nltk
from nltk.corpus import stopwords

# Downloaded the stopwords package
nltk.download('stopwords')
nltk.download('punkt')


SAVE_INTERVAL = 60  # Save every 5 minutes
last_save_time = time.time()  # Track the last save time




# Global variables
# tokens = {}
scraped_urls = set() # URLs that have been scraped
seen_urls = set()
unique_urls = {}
blacklisted_urls = set()
max_words = ["", 0] # URL with the most words
word_frequencies = Counter()
subdomains = {}



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
        blacklisted_urls.add(url)
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
    page_text = soup.get_text(separator=" ")
    words = extract_words(page_text)
    word_count = len(words)
    word_frequencies.update(words)




    base_url = url.split('#')[0]  # Remove fragment
    unique_urls[base_url] = word_count
    
    if word_count > max_words[1] and "wordlist" not in url:
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

    if len(links) < 5:
        return []

    current_time = time.time()
    if current_time - last_save_time >= SAVE_INTERVAL:
        save_report()
        last_save_time = current_time  # Update the last save time

    
    
    return list(links)


def extract_words(text):
    stop_words = set(stopwords.words('english'))
    stop_words.update(["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december", r"\b(19|20)\d{2}\b"])

    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    tokenized_words = nltk.word_tokenize(' '.join(words))
    # Only include words that are alphabetic, have a length >= 3, and are not in STOP_WORDS
    non_stop_words = [
        word for word in tokenized_words if word.isalpha() and len(word) >= 3 and word not in stop_words
    ]

    return non_stop_words




def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    global blacklisted_urls
    try:
        parsed = urlparse(url)
        if parsed.scheme not in (["http", "https"]):
            return False
        
        if parsed.query:
            return False
   
        # filter unwanted urls to avoid traps
    
        unwanted_patterns = [
            "filter", "tribe-bar-date=", "/events/", "outlook-ical=", "ical=1", 
            "/month/", "/list/", "eventDisplay=past", "?share=", "pdf", 
            "redirect", "#comment", "#respond", "#comments", 
            "seminar_id=", "archive_year=", "/department-seminars/", "/seminar-series/",
            "year", "month", "day", "date", "week", "calendar", 
            "archive", "history", "past", "previous", "footer", "header", "meta", "nav",
            "wordlist", "dictionary", "glossary", 
            # Date formatted patterns or Year
            r"^\d{4}-\d{2}-\d{2}$", r"^\d{2}-\d{2}-\d{4}$", r"\b(19|20)\d{2}\b"
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
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False
        if url in blacklisted_urls:
            return False
        
        # Filter out URLs with unwanted patterns
        if any(pattern in url for pattern in unwanted_patterns):
            return False
      
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"war|apk|sql|html|img|ppsx|ps"
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


def generate_trigram(list_of_words):

    trigrams = []
    
    for i in range(len(list_of_words)-2):
        trigram = (list_of_words[i], list_of_words[i+1], list_of_words[i+2])
        if trigram not in trigrams:
            trigrams.append(trigram)
    
    return trigrams

def filter_trigram(trigrams):
    
    select_trigrams = set()

    #Compute a "hash value for each trigram and filter out using mod"
    for trigram in trigrams:
        value = 0
        for char in trigram:
            number = ord(char)
            value += number
        
        if value % 4 == 0:
            select_trigrams.add(trigram)
    
    return select_trigrams


def check_similarity(curr_hash, stored_hash):
    
    intersection = curr_hash.intersection(stored_hash)
    union = curr_hash.union(stored_hash)

    if not union:  # Avoid division by zero
        return 0.0

    # Calculate similarity
    similarity = len(intersection) / len(union)
    return similarity

def is_near_duplicates(curr_hash_set, url_hashes):

    threshold = .5
    for url, fingerprints in url_hashes:
        similarity = check_similarity(curr_hash_set, set(fingerprints))

        if similarity >= threshold:
            return True
        
    
    return False 


def simhash(words, url_hashes):
    if not url_hashes:
        return True

    trigrams = generate_trigram(words)
    selected_trigrams = filter_trigram(trigrams)

    if is_near_duplicates(selected_trigrams, url_hashes):
        return False

    return True



def save_report(filename="CrawlerReport.txt"):
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



def links(html_path):
    with open(html_path, "rb") as file:
        content = file.read()
        detected = chardet.detect(content)
        encoding = detected['encoding'] if detected['encoding'] else 'utf-8'
        decoded_content = content.decode(encoding, errors='ignore')

    soup = BeautifulSoup(decoded_content, "lxml")

    if CheckLowInformation(soup):
        print("Is low info")

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    for tag in soup.find_all(['script', 'style']):
        tag.extract()
    
    for tag in soup(['footer', 'header', 'meta', 'nav']):
        tag.extract()

    page_text = soup.get_text()
    words = extract_words(page_text)
    word_count = len(words)  # Total word count

    print("Words in page:", words)
    print("Total word count:", word_count)

    keywords = ["login", "sign in", "signup", "password", "calendar"]
    for keyword in keywords:
        if keyword in page_text.lower():  # Convert to lowercase for case-insensitive search
            print(f"The keyword '{keyword}' is present in the page.")
