# Firewall

Hi! Thank you for the opportunity to complete this coding challenge. Here's some context on my submission.

- This seemed like a search question: find if a given input is present in a given set. So I knew I wanted to a lot of preprocessing at the start to produce some sort of data structure that would be be optimal for searching. I went into this knowing I wanted to achieve around logarithmic runtime, so there would be some sort of sorting involved so I could make use of binary search, which is log(n) time. I wasn't 100% sure how to achieve this with range inputs, that would be given out of order and overlapping, so I went to my best friends Google and Stackoverflow. I found this post, which is the inspiration for my solution:

https://stackoverflow.com/questions/23639361/fast-checking-of-ranges-in-python
(I might probably also cite this inline my code, depending on the conventions of the codebase I'm working with. I personally think it's not a bad idea to do so.)

Basically I want to parse the range inputs into a list such that even indices mark range starts and odd indices mark range ends. So then one could leverage python's bisect to find where a given IP address or port would land - if it would land at an odd index, you know it's within the bounds of an acceptable range, or not if even. Bisect runs in log(n) time, so this approach satisfied my desired performance charcteristics. I just had to sort my input files.

- I've done the merge intervals problem on leetcode before, so I had an idea of the cases I needed to cover. Nevertheless, I feel like my if statements got a little nested and hard to follow, and I didn't have the time to test if it did in fact cover all the possible interval merging and inserting cases properly. However, I did try to add a few comments on why the conditionals are the way they are. If I had the chance to do another pass, I would definitely work on clarifying that logic, or at least better communicating my reasoning. Because there is inserting and prepending involved in my constructor function, __init__ runs in n^2 time, I think. It's a perfectly acceptable tradeoff for O(log(n)) lookup time, I think. I use O(n) space.

- I spent a lot of time at the outset planning out my algorithm to get it to that log(n) runtime, and as a result, only had time to run the most trivial of cases. Given more time, I would spend the bulk of it testing my interval sorting and merging algorithm on both port and IP addresses. I would input different csvs that would forcet the algorithm to insert intervals at the start, end, and middle, to modify an existing interval without deleting entries, to modify existing intervals while deleting entries in between, to merge all existing intervals into one signal entry, and probably a few more cases that aren't coming to mind now. Testing has never been my strong suit, I admit, and thinking in that mindset is something I want to get better at. I do think I somewhat make up for it by doing a lot of exploratory research and writing decent spec sheets, even before a small project like this.

- Another optimization suggested in that stackoverflow page is to use numpy's search function instead of bisect, and the posted included proof that using that method along with numpy arrays is faster. I didn't have time to convert and do benchmarking, but that is definitely something I would explore. I am skeptical that a plain list is the best option here. At the very least, a deque would improve performance for inserting and removing from the head of the list, which may happen a fair amount. I could benchmark a deque (or other data structures if research reveals them) for their performance with bisect.

- Also, the code for sorting IP addresses and sorting port ranges is virtually identical, so I would refactor them out into their own method so it was DRY. Sorry, I should have done during the 90 minutes, but it wasn't a priority as much as getting the code running.

- Also, I don't want to cheat but there's an error on lines 56 and 96: it should be `elif x is 0 and y is 0:`. Again, testing all the possible merging paths would have caught this. My bad.

All of the teams sounds great and I'd be happy anywhere, but I think the policy team would give me the most unique experience, so that is most interesting to me.
