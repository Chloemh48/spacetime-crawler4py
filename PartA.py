import sys


#Function will error check the file for file does not exist and if the file is not utf-8 encoded
#Time complexity is O(1) for error checking
#returns file object
def read_file(file_path):

    try:
        file = open(file_path, "r", encoding="utf-8")
        return file
    
    except FileNotFoundError:
        print(f"Error: the file ' {file_path}' is not found")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"Error: the file' {file_path}' is not UTF-8")
        sys.exit(1)
    
    except Exception as e:
        print(f"Unexpected error found when trying to open file '{file_path}'")
        sys.exit(1)


#Function does not read whole text file and stores it into ram
#Time complexity is O(n) where n is the amount of characters in the file
#yield makes it so that tokens are used when needed not loading all at once
def tokenize(file_path):
    file = read_file(file_path)
    #Checking each line in the file and for each line check each character to store it in the map for tokens
    for line in file:
        token = ""
        for character in line:
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


#Call functions   

if len(sys.argv) < 2:
    print(f'Did not provide enough for file path')
    sys.exit(1)

printFrequencies(computeWordFrequencies(tokenize(sys.argv[1])))